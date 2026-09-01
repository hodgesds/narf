//! Atheros AR81xx (atl1c) Gigabit Ethernet driver.
//!
//! Covers the Attansic / Atheros L1c / L2c family that ships on a
//! wide swathe of consumer laptops (Acer, Asus, MSI, Gigabyte) — the
//! same chip Linux's `drivers/net/ethernet/atheros/atl1c/` services.
//! The hard cutover replaces the prior AR9xxx-Wi-Fi stub that lived
//! at this module path; clean-room re-targeted at the wired NIC for
//! Stage-4 net bring-up.
//!
//! ## Reference
//!
//! Linux `drivers/net/ethernet/atheros/atl1c/atl1c_hw.h` +
//! `atl1c_hw.c` + `atl1c_main.c` (GPL-2.0). NARF is GPL-2.0-or-later
//! since 2026-05-20 so direct register adaptation is in-license.
//!
//! ### Register surface (subset used here)
//!
//! | offset | name              | description                              |
//! |--------|-------------------|------------------------------------------|
//! | 0x1400 | MASTER_CTRL       | Master reset, clock select               |
//! | 0x1480 | MAC_CTRL          | MAC config — RX/TX enable, duplex, FC    |
//! | 0x1488 | MAC_STA_ADDR_HI   | Station address high 16 bits             |
//! | 0x148C | MAC_STA_ADDR_LO   | Station address low 32 bits              |
//! | 0x1414 | MDIO_CTRL         | MII PHY register access                  |
//! | 0x144C | TWSI_CTRL         | EEPROM I2C bus control                   |
//! | 0x15F8 | TPD_RING_HEAD     | TX (Packet-Descriptor) ring base lo32    |
//! | 0x15D0 | RFD_RING_HEAD     | RFD (free-buffer) ring base lo32         |
//! | 0x15F0 | RRS_RING_HEAD     | RRS (return-status) ring base lo32       |
//! | 0x1600 | IMR               | Interrupt Mask                           |
//! | 0x1604 | ISR               | Interrupt Status                         |
//!
//! ### Ring design
//!
//! `atl1c` uses a **split-RX** design that's unusual for cheap-NIC
//! silicon: the host posts free buffers via the RFD ring; the NIC
//! reports completed frames via the RRS ring (which references back
//! into the RFD slot). The TX side is a single TPD ring.
//!
//! Stage-2 bring-up here implements TPD (TX) + RFD + RRS (RX) and an
//! IRQ-mask + ISR write-1-clear pattern. EEPROM read for the
//! permanent MAC mirrors `atl1c_get_permanent_address` (TWSI CMD =
//! 0x1, polled until DONE bit clears).

#![allow(dead_code)]

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::sync::Arc;
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, RX_RING_N, TX_RING_N};

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Atheros Communications (Attansic legacy ids share this).
pub const ATL_VENDOR: u16 = 0x1969;

/// L1c — AR8131 Gigabit (PCIe).
pub const ATL_DEV_AR8131: u16 = 0x1063;
/// L2c — AR8132 Fast Ethernet (PCIe).
pub const ATL_DEV_AR8132: u16 = 0x1062;
/// L1d — AR8151 v2.
pub const ATL_DEV_AR8151_V2: u16 = 0x1083;
/// L1d — AR8151 (rev 1).
pub const ATL_DEV_AR8151: u16 = 0x1090;
/// L2c — AR8152.
pub const ATL_DEV_AR8152: u16 = 0x1091;
/// L1e — AR8161 Gigabit.
pub const ATL_DEV_AR8161: u16 = 0x2060;
/// L2e — AR8162 Fast Ethernet.
pub const ATL_DEV_AR8162: u16 = 0x2062;
/// L1f — AR8171 Gigabit (newer revision).
pub const ATL_DEV_AR8171: u16 = 0x10A1;

/// Full PCI match table. Mirrors the subset of Linux's
/// `atl1c_pci_tbl[]` that ships on consumer laptops.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    ATL_DEV_AR8131,
    ATL_DEV_AR8132,
    ATL_DEV_AR8151_V2,
    ATL_DEV_AR8151,
    ATL_DEV_AR8152,
    ATL_DEV_AR8161,
    ATL_DEV_AR8162,
    ATL_DEV_AR8171,
];

// ── Register offsets (atl1c_hw.h) ───────────────────────────────────

const REG_MASTER_CTRL: u64 = 0x1400;
const REG_MDIO_CTRL: u64 = 0x1414;
const REG_TWSI_CTRL: u64 = 0x144C;
const REG_MAC_CTRL: u64 = 0x1480;
const REG_MAC_STA_ADDR_HI: u64 = 0x1488;
const REG_MAC_STA_ADDR_LO: u64 = 0x148C;
const REG_RFD_RING_HEAD: u64 = 0x15D0;
const REG_RFD_RING_HEAD_HI: u64 = 0x15D4;
const REG_RFD_BUFFER_SIZE: u64 = 0x15D8;
const REG_RRS_RING_HEAD: u64 = 0x15F0;
const REG_TPD_RING_HEAD: u64 = 0x15F8;
const REG_TPD_RING_HEAD_HI: u64 = 0x15FC;
const REG_RING_COUNT: u64 = 0x1600;
const REG_IMR: u64 = 0x1604;
const REG_ISR: u64 = 0x1608;

// ── MASTER_CTRL bits ────────────────────────────────────────────────

/// Bit 0: software master reset — self-clearing after the chip
/// finishes re-arming its internal FIFOs. Mirrors
/// `MASTER_CTRL_SOFT_RST` in `atl1c_hw.h`.
pub const MASTER_CTRL_SOFT_RST: u32 = 1 << 0;
/// Bit 12: MTimer enable. Stage-2 leaves this off (drives the on-die
/// hardware coalesce timer); polled / IRQ pumps don't need it.
pub const MASTER_CTRL_MTIMER_EN: u32 = 1 << 12;

// ── MAC_CTRL bits ───────────────────────────────────────────────────

pub const MAC_CTRL_TX_EN: u32 = 1 << 0;
pub const MAC_CTRL_RX_EN: u32 = 1 << 1;
pub const MAC_CTRL_TX_FLOW: u32 = 1 << 2;
pub const MAC_CTRL_RX_FLOW: u32 = 1 << 3;
pub const MAC_CTRL_LOOPBACK: u32 = 1 << 4;
pub const MAC_CTRL_DUPLEX: u32 = 1 << 5;
pub const MAC_CTRL_ADD_CRC: u32 = 1 << 6;
pub const MAC_CTRL_PAD: u32 = 1 << 7;
/// Speed select: bits[21:20] = 0b10 → 1000 Mbit, 0b01 → 100 Mbit.
pub const MAC_CTRL_SPEED_SHIFT: u32 = 20;
pub const MAC_CTRL_SPEED_1000: u32 = 0b10 << MAC_CTRL_SPEED_SHIFT;
pub const MAC_CTRL_SPEED_100: u32 = 0b01 << MAC_CTRL_SPEED_SHIFT;
pub const MAC_CTRL_BC_EN: u32 = 1 << 26;
pub const MAC_CTRL_MC_EN: u32 = 1 << 25;
pub const MAC_CTRL_PROMIS_EN: u32 = 1 << 15;

// ── MDIO_CTRL bits (PHY access) ─────────────────────────────────────

/// Bits[15:0] = data.
/// Bits[20:16] = register address (Clause 22).
/// Bit 21 = read=1 / write=0 in `atl1c` notation.
/// Bit 30 = start command.
/// Bit 31 = busy (clears when access completes).
pub const MDIO_DATA_MASK: u32 = 0xFFFF;
pub const MDIO_REG_SHIFT: u32 = 16;
pub const MDIO_OP_READ: u32 = 1 << 21;
pub const MDIO_START: u32 = 1 << 30;
pub const MDIO_BUSY: u32 = 1 << 31;

/// MII Clause-22 standard register addresses (same as `rtl_phy`).
pub const MII_BMCR: u8 = 0x00;
pub const MII_BMSR: u8 = 0x01;

/// BMSR.LINK_STATUS — bit 2 (sticky-low; read twice for a current
/// reading per IEEE 802.3 §22.2.4.2).
pub const BMSR_LINK_STATUS: u16 = 1 << 2;
/// BMSR.AUTONEG_COMPLETE — bit 5.
pub const BMSR_AUTONEG_COMPLETE: u16 = 1 << 5;

// ── TWSI / EEPROM bits ──────────────────────────────────────────────

/// SW LD START — kicks the on-die EEPROM loader at the address in
/// bits[15:8]. Self-clears when done. Mirrors `TWSI_CTRL_LD_START` in
/// `atl1c_hw.h`.
pub const TWSI_CTRL_LD_START: u32 = 1 << 11;
pub const TWSI_CTRL_LD_SLV_ADDR_SHIFT: u32 = 8;
pub const TWSI_CTRL_LD_SLV_ADDR_MASK: u32 = 0x07 << TWSI_CTRL_LD_SLV_ADDR_SHIFT;
/// Bit indicating SW loader is currently active.
pub const TWSI_CTRL_LD_EXIST: u32 = 1 << 23;

// ── IMR / ISR bits ──────────────────────────────────────────────────

pub const INT_SMB: u32 = 1 << 0;
pub const INT_TX_PKT: u32 = 1 << 1;
pub const INT_RX_PKT0: u32 = 1 << 2;
pub const INT_TX_DMA: u32 = 1 << 3;
pub const INT_RX_DMA: u32 = 1 << 4;
pub const INT_GPHY: u32 = 1 << 7;
pub const INT_PHY_LINKDOWN: u32 = 1 << 8;
pub const INT_PCIE_LNKDOWN: u32 = 1 << 30;
pub const INT_DIS_INT: u32 = 1 << 31;

/// Default IRQ mask used by Stage-2 RX/TX pumps.
pub const fn default_intr_mask() -> u32 {
    INT_TX_PKT | INT_RX_PKT0 | INT_GPHY | INT_PHY_LINKDOWN
}

// ── Descriptor in-memory shapes ─────────────────────────────────────

/// TX packet descriptor (TPD) — 16 bytes. Per `atl1c_main.c`'s
/// `struct atl1c_tpd_desc`, the first u32 carries length + control
/// flags; the next two carry the 64-bit buffer address; the last
/// u32 carries VLAN tags + extended flags. Stage-2 only uses the
/// length + EOP/SOP + OWN bits.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct Tpd {
    /// Bits[15:0] = buffer length.
    /// Bit 16 = SOP (start of packet).
    /// Bit 17 = EOP (end of packet).
    /// Bit 31 = OWN (host-owned=0, NIC-owned=1).
    word0: u32,
    /// VLAN + checksum-offload flags. Stage-2 leaves zero.
    word1: u32,
    addr_lo: u32,
    addr_hi: u32,
}
const _: () = assert!(core::mem::size_of::<Tpd>() == 16);

/// RFD (free-buffer) descriptor — 8 bytes. Host posts the physical
/// address of a 2 KiB buffer; the NIC drains DMA into it and reports
/// completion via the matching RRS slot. Per `atl1c_main.c`'s
/// `struct atl1c_rx_free_desc`.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default)]
struct Rfd {
    addr_lo: u32,
    addr_hi: u32,
}
const _: () = assert!(core::mem::size_of::<Rfd>() == 8);

/// RRS (return-status) descriptor — 16 bytes. Per
/// `struct atl1c_recv_ret_status`:
///   word0: hash low
///   word1: hash high
///   word2: bits[31] OWN, bits[19:0] frame length, bits[27:20] = RFD slot
///   word3: per-frame status (error / vlan / csum)
/// Stage-2 only consults `word2`'s OWN + length + RFD-slot fields.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct Rrs {
    word0: u32,
    word1: u32,
    word2: u32,
    word3: u32,
}
const _: () = assert!(core::mem::size_of::<Rrs>() == 16);

/// RRS.word2 bit layout.
pub const RRS_OWN: u32 = 1 << 31;
/// Frame length lives in bits[19:0].
pub const RRS_LEN_MASK: u32 = 0x000F_FFFF;
/// RFD index lives in bits[27:20].
pub const RRS_RFD_INDEX_SHIFT: u32 = 20;
pub const RRS_RFD_INDEX_MASK: u32 = 0xFF << RRS_RFD_INDEX_SHIFT;

/// TPD.word0 bit layout.
pub const TPD_LEN_MASK: u32 = 0xFFFF;
pub const TPD_SOP: u32 = 1 << 16;
pub const TPD_EOP: u32 = 1 << 17;
pub const TPD_OWN: u32 = 1 << 31;

// ── Sizing constants ────────────────────────────────────────────────

/// TX ring depth. atl1c caps each ring at 1024; 256 is plenty for
/// Stage-2 and matches the r8169 sizing.
pub const TPD_RING_LEN: usize = 256;
/// RFD ring length. atl1c requires RFD count == RRS count.
pub const RFD_RING_LEN: usize = 256;
/// RRS ring length — paired with RFD 1:1.
pub const RRS_RING_LEN: usize = 256;

/// RX buffer size — 2 KiB per slot, programmed into REG_RFD_BUFFER_SIZE.
pub const RX_BUF_LEN: usize = 2048;

const TPD_RING_BYTES: usize = TPD_RING_LEN * 16;
const RFD_RING_BYTES: usize = RFD_RING_LEN * 8;
const RRS_RING_BYTES: usize = RRS_RING_LEN * 16;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    ResetTimeout,
    FrameTooLong,
    TxRingFull,
    TxTimeout,
    EepromTimeout,
}

// ── Driver state ────────────────────────────────────────────────────

/// A live AR81xx (atl1c) controller. Holds the MMIO mapping, the
/// TPD + RFD + RRS rings, and the RX buffer pool.
pub struct AtlNic {
    mmio: MmioRegion,
    tpd_ring: DmaBuffer,
    tpd_pool: alloc::vec::Vec<DmaBuffer>,
    tpd_head: IrqSafeSpinLock<u32>,
    rfd_ring: DmaBuffer,
    rfd_pool: alloc::vec::Vec<DmaBuffer>,
    rrs_ring: DmaBuffer,
    rrs_head: IrqSafeSpinLock<u32>,
    pub mac: [u8; 6],
    pub link_up: bool,
    pub speed_1000: bool,
    pub duplex_full: bool,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: every mutable field is either confined to the driver thread that
// owns the device or guarded by an `IrqSafeSpinLock`; `MmioRegion` and the
// `DmaBuffer` rings are raw device-memory handles with no thread affinity,
// so moving an `AtlNic` between threads is sound.
unsafe impl Send for AtlNic {}
// SAFETY: all interior mutability (ring heads and IPC endpoints) is behind
// `IrqSafeSpinLock`; the remaining fields are read-only after `bring_up`, so
// `&AtlNic` can be shared across threads without data races.
unsafe impl Sync for AtlNic {}

impl core::fmt::Debug for AtlNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AtlNic")
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("speed_1000", &self.speed_1000)
            .field("duplex_full", &self.duplex_full)
            .finish_non_exhaustive()
    }
}

impl AtlNic {
    /// Bring up the controller. Sequence mirrors
    /// `atl1c_reset_mac` + `atl1c_configure` in Linux's `atl1c_main.c`:
    /// 1. Software master reset; poll `MASTER_CTRL_SOFT_RST` low.
    /// 2. Read MAC from `MAC_STA_ADDR_{HI,LO}` (loaded from EEPROM
    ///    by the chip's on-die loader at power-on).
    /// 3. Allocate + program TPD / RFD / RRS rings.
    /// 4. Enable MAC (RX + TX, broadcast / multicast accept).
    /// 5. Snapshot PHY BMSR for link state.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, NicError> {
        // BAR0 carries the operational register block.
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| NicError::BarMapFailed)?;

        // 1. Software reset. Linux pulls `MASTER_CTRL_SOFT_RST` and
        //    waits up to ~50 µs (`AT_HW_MAX_IDLE_DELAY = 10` * 50 µs);
        //    we use the responsive_spin_until pump with a 100 ms cap.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_MASTER_CTRL, MASTER_CTRL_SOFT_RST);
        }
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { mmio.read32(REG_MASTER_CTRL) } & MASTER_CTRL_SOFT_RST == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(NicError::ResetTimeout);
        }

        // 2. Read MAC station address. The chip's loader populates
        //    these registers from EEPROM during PCIe bring-up;
        //    `atl1c_get_permanent_address` reads them directly with
        //    no further action needed (TWSI dance is only required
        //    when the loader is disabled; we assume EEPROM-present).
        // SAFETY: same.
        let hi = unsafe { mmio.read32(REG_MAC_STA_ADDR_HI) };
        // SAFETY: same.
        let lo = unsafe { mmio.read32(REG_MAC_STA_ADDR_LO) };
        let mac = [
            ((hi >> 8) & 0xFF) as u8,
            (hi & 0xFF) as u8,
            ((lo >> 24) & 0xFF) as u8,
            ((lo >> 16) & 0xFF) as u8,
            ((lo >> 8) & 0xFF) as u8,
            (lo & 0xFF) as u8,
        ];

        // 3. Allocate rings + RX buffer pool. `alloc_coherent` returns
        //    zeroed pages — every TPD/RRS descriptor starts host-owned
        //    (OWN=0), which is what we want until we publish work /
        //    until the NIC fills an RRS slot.
        let tpd_ring =
            alloc_coherent(TPD_RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let rfd_ring =
            alloc_coherent(RFD_RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let rrs_ring =
            alloc_coherent(RRS_RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;

        let mut tpd_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(TPD_RING_LEN);
        for _ in 0..TPD_RING_LEN {
            tpd_pool
                .push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?);
        }
        let mut rfd_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RFD_RING_LEN);
        for _ in 0..RFD_RING_LEN {
            rfd_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }

        // 4a. Pre-fill RFD ring: each slot points at its pooled
        //     buffer. NIC consumes the RFD ring left-to-right; the
        //     RRS ring reports back which RFD slot was used.
        let rfd_phys = rfd_ring.phys_addr().raw();
        for (i, buf) in rfd_pool.iter().enumerate() {
            let buf_phys = buf.phys_addr().raw();
            let d = Rfd {
                addr_lo: buf_phys as u32,
                addr_hi: (buf_phys >> 32) as u32,
            };
            // SAFETY: `rfd_phys` is the identity-mapped base of the freshly
            // allocated RFD ring; `i < RFD_RING_LEN` (loop bound) so the slot
            // at `rfd_phys + i*8` lies within the ring's mapped 8-byte stride.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rfd_phys + (i * 8) as u64).kernel_mut_ptr::<Rfd>(),
                    d,
                );
            }
        }

        // 4b. Program ring bases. The low 32 bits land at the *HEAD
        //     offset; the high 32 bits at HEAD_HI. The chip's high-32
        //     of the RFD/RRS bases is shared (a single common DMA
        //     window); we program it on TPD_RING_HEAD_HI.
        let tpd_phys = tpd_ring.phys_addr().raw();
        let rrs_phys = rrs_ring.phys_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_TPD_RING_HEAD, tpd_phys as u32);
            mmio.write32(REG_TPD_RING_HEAD_HI, (tpd_phys >> 32) as u32);
            mmio.write32(REG_RFD_RING_HEAD, rfd_phys as u32);
            mmio.write32(REG_RFD_RING_HEAD_HI, (rfd_phys >> 32) as u32);
            mmio.write32(REG_RRS_RING_HEAD, rrs_phys as u32);
            // Ring depth — packed: bits[31:16] = RFD len, bits[15:0] = TPD len.
            let counts = ((RFD_RING_LEN as u32) << 16) | (TPD_RING_LEN as u32);
            mmio.write32(REG_RING_COUNT, counts);
            // Per-slot RX buffer size (no per-descriptor field on this chip).
            mmio.write32(REG_RFD_BUFFER_SIZE, RX_BUF_LEN as u32);
        }

        // 5. MAC config: enable TX + RX, accept broadcast +
        //    multicast, append CRC + pad shorts, default to 1G FD.
        //    Speed bits are resolved against the PHY auto-neg state
        //    in a follow-up; the chip handles MAC-PHY speed switch
        //    autonomously on the AR8131 family.
        // SAFETY: same.
        unsafe {
            mmio.write32(
                REG_MAC_CTRL,
                MAC_CTRL_TX_EN
                    | MAC_CTRL_RX_EN
                    | MAC_CTRL_DUPLEX
                    | MAC_CTRL_ADD_CRC
                    | MAC_CTRL_PAD
                    | MAC_CTRL_BC_EN
                    | MAC_CTRL_MC_EN
                    | MAC_CTRL_SPEED_1000,
            );
        }

        // 6. Mask all IRQs at IMR for now; write-1-clear ISR.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMR, 0);
            mmio.write32(REG_ISR, 0xFFFF_FFFF);
        }

        // 7. PHY snapshot — read BMSR. IEEE 802.3 §22.2.4.2 says the
        //    LinkStatus bit is *latched low* so the first read after
        //    a reset may report no link even on a live cable; we
        //    capture whatever the PHY currently says and let the
        //    link-watch path re-poll.
        // SAFETY: `mmio` is the BAR0 mapping this `bring_up` owns exclusively
        // (per its `# Safety` contract), satisfying `read_phy`'s requirement
        // that the caller own the device's MMIO BAR.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let bmsr = unsafe { read_phy(&mmio, MII_BMSR) }.unwrap_or(0);
        let link_up = bmsr & BMSR_LINK_STATUS != 0;
        let an_complete = bmsr & BMSR_AUTONEG_COMPLETE != 0;

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let atl = Arc::new(Self {
            mmio,
            tpd_ring,
            tpd_pool,
            tpd_head: IrqSafeSpinLock::new(0),
            rfd_ring,
            rfd_pool,
            rrs_ring,
            rrs_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            speed_1000: an_complete,
            duplex_full: true,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn pumps
        spawn_pumps(atl.clone(), rx_prod, tx_cons);

        Arc::try_unwrap(atl).map_err(|_| NicError::NoMemory)
    }

    /// Transmit a single Ethernet frame. Polled completion.
    pub fn transmit(&self, frame: &[u8]) -> Result<(), NicError> {
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
        }
        let mut head_g = self.tpd_head.lock();
        let slot = (*head_g) as usize % TPD_RING_LEN;
        let buf_phys = self.tpd_pool[slot].phys_addr().raw();

        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(buf_phys + i as u64).kernel_mut_ptr::<u8>(),
                    *b,
                );
            }
        }

        let ring_phys = self.tpd_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring; slot < TPD_RING_LEN.
        let cur = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if cur & TPD_OWN != 0 {
            return Err(NicError::TxRingFull);
        }

        let w0 = (frame.len() as u32 & TPD_LEN_MASK) | TPD_SOP | TPD_EOP | TPD_OWN;
        let d = Tpd {
            word0: w0,
            word1: 0,
            addr_lo: buf_phys as u32,
            addr_hi: (buf_phys >> 32) as u32,
        };
        // Publish addr/vlan first, then OWN — same fence discipline
        // as the r8169 path.
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                d.word1,
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
                d.word0,
            );
        }
        compiler_fence(Ordering::SeqCst);

        // Doorbell: bump the TPD producer index via REG_RING_COUNT's
        // upper 16 bits would be wrong — the chip auto-prefetches as
        // soon as OWN flips. No software doorbell needed on this part.

        *head_g = (*head_g + 1) % (TPD_RING_LEN as u32);
        drop(head_g);

        // Poll for OWN → 0. responsive_spin_until ticks sleep_pumps.
        let owned = narf_scheduler::responsive_spin_until(
            // SAFETY: same.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>()) } & TPD_OWN == 0,
            narf_time::Deadline::after_ms(250),
        );
        if !owned {
            return Err(NicError::TxTimeout);
        }
        Ok(())
    }

    /// Drain one received frame from the RRS ring.  Returns `Some` if
    /// a descriptor is ready, `None` if the head is still NIC-owned.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let mut head_g = self.rrs_head.lock();
        let slot = (*head_g) as usize % RRS_RING_LEN;
        let ring_phys = self.rrs_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring.
        let word2 = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 8).kernel_ptr::<u32>())
        };
        // NIC writes OWN=1 when it has populated the slot.
        if word2 & RRS_OWN == 0 {
            return None;
        }

        let len = (word2 & RRS_LEN_MASK) as usize;
        let rfd_slot = ((word2 & RRS_RFD_INDEX_MASK) >> RRS_RFD_INDEX_SHIFT) as usize;
        if rfd_slot >= RFD_RING_LEN {
            // Bad descriptor — clear OWN to recycle and skip.
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                    0,
                );
            }
            *head_g = (*head_g + 1) % (RRS_RING_LEN as u32);
            return None;
        }
        let buf_phys = self.rfd_pool[rfd_slot].phys_addr().raw();

        let copy_len = len.min(RX_BUF_LEN);
        let mut out = alloc::vec::Vec::with_capacity(copy_len);
        for i in 0..copy_len {
            // SAFETY: `buf_phys` is the identity-mapped base of this RFD slot's
            // DMA buffer; `i < copy_len <= RX_BUF_LEN`, so each byte read stays
            // within that DMA-coherent allocation. Volatile because the NIC
            // wrote the bytes via DMA.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            out.push(unsafe {
                core::ptr::read_volatile(
                    narf_memory::PhysAddr::new(buf_phys + i as u64).kernel_ptr::<u8>(),
                )
            });
        }

        // Rearm: clear OWN on RRS slot — the matching RFD slot
        // remains pre-armed (NIC tracks its own RFD consumer cursor).
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                0,
            );
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RRS_RING_LEN as u32);
        Some(out)
    }

    /// Enable RX-pkt + TX-pkt IRQs at IMR.
    pub fn enable_irqs(&self) {
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IMR, default_intr_mask());
        }
    }

    /// Drain + write-1-clear the ISR.
    pub fn ack_isr(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        let s = unsafe { self.mmio.read32(REG_ISR) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(REG_ISR, s);
        }
        s
    }

    /// Re-evaluate link state by reading BMSR.
    pub fn refresh_link_state(&mut self) -> bool {
        // SAFETY: same.
        let bmsr = unsafe { read_phy(&self.mmio, MII_BMSR) }.unwrap_or(0);
        self.link_up = bmsr & BMSR_LINK_STATUS != 0;
        self.link_up
    }

    /// Read a PHY register over MDIO.
    pub fn phy_read(&self, reg: u8) -> Result<u16, NicError> {
        // SAFETY: identity-mapped MMIO.
        unsafe { read_phy(&self.mmio, reg) }
    }
}

// ── PHY MDIO helper ─────────────────────────────────────────────────

/// Issue a Clause-22 read against the PHY through MDIO_CTRL.  Mirrors
/// `atl1c_read_phy` — set REG_ADDR + READ + START, poll BUSY low.
///
/// # Safety
/// Caller must own the device's MMIO BAR.
unsafe fn read_phy(mmio: &MmioRegion, reg: u8) -> Result<u16, NicError> {
    let cmd = ((reg as u32) << MDIO_REG_SHIFT) | MDIO_OP_READ | MDIO_START;
    // SAFETY: caller-asserted ownership.
    unsafe {
        mmio.write32(REG_MDIO_CTRL, cmd);
    }
    let done = narf_scheduler::responsive_spin_until(
        // SAFETY: same.
        || unsafe { mmio.read32(REG_MDIO_CTRL) } & MDIO_BUSY == 0,
        narf_time::Deadline::after_ms(50),
    );
    if !done {
        return Err(NicError::ResetTimeout);
    }
    // SAFETY: same.
    let v = unsafe { mmio.read32(REG_MDIO_CTRL) };
    Ok((v & MDIO_DATA_MASK) as u16)
}

// ── EEPROM read helper (Linux atl1c_get_permanent_address) ──────────

/// Issue the EEPROM software loader and return the readback MAC.
///
/// On boards where the chip's auto-load fails to populate
/// MAC_STA_ADDR_{HI,LO}, Linux falls back to firing the TWSI bus
/// software loader (`TWSI_CTRL_LD_START`) which re-runs the I2C
/// EEPROM sequence. The loader self-clears the START bit when done.
///
/// # Safety
/// Caller must own the device's MMIO BAR.
pub unsafe fn eeprom_reload_mac(mmio: &MmioRegion) -> Result<[u8; 6], NicError> {
    // SAFETY: caller-asserted ownership.
    let prev = unsafe { mmio.read32(REG_TWSI_CTRL) };
    // SAFETY: same.
    unsafe {
        mmio.write32(REG_TWSI_CTRL, prev | TWSI_CTRL_LD_START);
    }
    let done = narf_scheduler::responsive_spin_until(
        // SAFETY: same.
        || unsafe { mmio.read32(REG_TWSI_CTRL) } & TWSI_CTRL_LD_START == 0,
        narf_time::Deadline::after_ms(100),
    );
    if !done {
        return Err(NicError::EepromTimeout);
    }
    // SAFETY: same.
    let hi = unsafe { mmio.read32(REG_MAC_STA_ADDR_HI) };
    // SAFETY: same.
    let lo = unsafe { mmio.read32(REG_MAC_STA_ADDR_LO) };
    Ok([
        ((hi >> 8) & 0xFF) as u8,
        (hi & 0xFF) as u8,
        ((lo >> 24) & 0xFF) as u8,
        ((lo >> 16) & 0xFF) as u8,
        ((lo >> 8) & 0xFF) as u8,
        (lo & 0xFF) as u8,
    ])
}

// ── Bring-up helpers used by smoke tests ────────────────────────────

/// Compose the MAC_CTRL value used during Stage-2 bring-up: TX + RX
/// enabled, broadcast + multicast accepted, default speed = 1G FD.
pub const fn default_mac_ctrl_value() -> u32 {
    MAC_CTRL_TX_EN
        | MAC_CTRL_RX_EN
        | MAC_CTRL_DUPLEX
        | MAC_CTRL_ADD_CRC
        | MAC_CTRL_PAD
        | MAC_CTRL_BC_EN
        | MAC_CTRL_MC_EN
        | MAC_CTRL_SPEED_1000
}

/// Compose the MASTER_CTRL reset value — pure SOFT_RST bit; clock-
/// select bits are auto-restored by the chip on reset clear.
pub const fn master_reset_value() -> u32 {
    MASTER_CTRL_SOFT_RST
}

/// Decode a hypothetical EEPROM-byte tuple into a MAC address. The
/// EEPROM layout writes the station address big-endian across two
/// 32-bit cells: HI in bytes[1:0] (low 16 of the MAC), LO in bytes
/// [3:0] (high 32 of the MAC, byte-reversed). This helper exposes
/// the decode logic so the EEPROM-read smoke can validate it without
/// hardware in the loop.
pub const fn mac_from_sta_addr(hi: u32, lo: u32) -> [u8; 6] {
    [
        ((hi >> 8) & 0xFF) as u8,
        (hi & 0xFF) as u8,
        ((lo >> 24) & 0xFF) as u8,
        ((lo >> 16) & 0xFF) as u8,
        ((lo >> 8) & 0xFF) as u8,
        (lo & 0xFF) as u8,
    ]
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<AtlNic>>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent:
/// returns `Ok(())` when the controller is already brought up.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER are both required — the chip DMAs the
    // descriptor rings + frame buffers and we map BAR0 as MMIO.
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

    // SAFETY: this probe just programmed the device's PCI command register
    // (MEM_SPACE | BUS_MASTER | INTX_DISABLE) and is the sole owner of
    // `device` for the duration of the call, satisfying `bring_up`'s
    // exclusive-ownership requirement over the BAR + cfg windows.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { AtlNic::bring_up(&device, &cap) } {
        Ok(d) => Arc::new(d),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    {
        // SAFETY: `dev` was just created via `Arc::new` and is the unique
        // strong reference at this point (no clone exists until the
        // `CONTROLLER` install below), so `Arc::as_ptr` yields a pointer to a
        // live, exclusively-owned `AtlNic` and the `&mut` borrow ends before
        // any clone is published.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let d = unsafe { &mut *(Arc::as_ptr(&dev) as *mut AtlNic) };
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
        let _ = narf_net::registry().register(&auth, AtlHwNic);
    }

    // Spawn pumps
    spawn_pumps(dev, rx_prod, tx_cons);

    Ok(())
}

fn spawn_pumps(
    device: Arc<AtlNic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        atheros_rx_pump(d1, rx_prod).await;
    });

    let d2 = device;
    narf_scheduler::spawn(async move {
        atheros_tx_pump(d2, tx_cons).await;
    });
}

async fn atheros_rx_pump(device: Arc<AtlNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
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

async fn atheros_tx_pump(device: Arc<AtlNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload());
    }
}

/// Register the driver against every documented AR81xx device id.
pub fn register_pci_driver() {
    for &did in SUPPORTED_DEVICE_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: ATL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        ATL_DEV_AR8131 => "atl1c-ar8131",
        ATL_DEV_AR8132 => "atl1c-ar8132",
        ATL_DEV_AR8151 => "atl1c-ar8151",
        ATL_DEV_AR8151_V2 => "atl1c-ar8151-v2",
        ATL_DEV_AR8152 => "atl1c-ar8152",
        ATL_DEV_AR8161 => "atl1c-ar8161",
        ATL_DEV_AR8162 => "atl1c-ar8162",
        ATL_DEV_AR8171 => "atl1c-ar8171",
        _ => "atl1c",
    }
}

/// `true` once `probe` has installed a controller.
#[derive(Debug)]
pub struct AtlHwNic;

impl narf_net::Interface for AtlHwNic {
    fn name(&self) -> &str {
        "eth7"
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

impl crate::HwNic for AtlHwNic {
    fn name(&self) -> &'static str {
        "eth7" // TODO: dynamic naming
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
        crate::NicModel::AtherosAtl1c
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        1 << 8
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

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&AtlNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

/// Mutable accessor.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut AtlNic) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("AtlNic static has multiple owners")))
}
