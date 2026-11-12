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
//! | 0x200   | WakeUpFlags       | WoL magic-pattern accept (issue #792)|
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

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use alloc::sync::Arc;
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};

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

// ── Suspend / resume register plans (issue #793) ────────────────────

/// Suspend / resume register plans over a minimal bank so fixtures
/// drive the exact program against a fake bank (end-to-end register
/// writes, no silicon) while the live path runs it against BAR0 via
/// [`MmioBank`]. Same shape as e1000's inline `pm` module.
///
/// * Suspend: mask interrupts (IRQ_MASK = 0), acknowledge pending
///   causes (IRQ_STATUS = all-ones — the same pair bring-up writes),
///   stop the RX/TX paths (RCV_CTL = 0, XMIT_CTL = 0 — the symmetric
///   stop of bring-up step 10's `nv_start_rxtx` enable), then run
///   the `nv_txrx_reset` dance (raise RESET | BIT2 | txrxctl_bits,
///   2 ms settle, lower by writing BIT2 | txrxctl_bits — the reset
///   bit is dropped by the explicit lowering write, per bring-up
///   step 1) to drain any in-flight DMA. The descriptor rings and
///   their programmed bases persist.
/// * Resume: re-enable the RX/TX paths (RCV_CTL =
///   RX_PATH_EN | START, XMIT_CTL = TX_PATH_EN | START). The
///   interrupt mask is NOT restored: the driver runs polled
///   (bring-up leaves IRQ_MASK = 0; no vector is wired), so
///   re-arming `IRQMASK_THROUGHPUT` would arm interrupts no
///   handler is wired to.
///
/// PHY: no PHY power-down. The PHY re-negotiation (BMCR
/// ANENABLE | ANRESTART via `mii_rw`) lives in `resume`, next to
/// the link re-read: it needs a live MDIO transaction, which the
/// register plan does not do.
mod pm {
    use super::{
        RCV_CTL_RX_PATH_EN, RCV_CTL_START, REG_IRQ_MASK, REG_IRQ_STATUS, REG_RCV_CTL,
        REG_TX_RX_CONTROL, REG_XMIT_CTL, TXRXCTL_BIT2, TXRXCTL_RESET, XMIT_CTL_START,
        XMIT_CTL_TX_PATH_EN,
    };
    use narf_bus::MmioRegion;

    /// Minimal register-bank abstraction so the register
    /// conversation can be exercised against a fake bank in
    /// fixtures and against real MMIO in the driver via
    /// [`MmioBank`]. The `delay_ms` step is the `nv_txrx_reset`
    /// settle: bring-up implements it as a pure delay via
    /// `responsive_spin_until(|| false, …)`.
    pub trait RegBank {
        fn read32(&self, offset: u64) -> u32;
        fn write32(&self, offset: u64, value: u32);
        fn delay_ms(&self, ms: u64);
    }

    /// [`RegBank`] over a real BAR0 mapping.
    #[derive(Debug)]
    pub struct MmioBank<'a> {
        mmio: &'a MmioRegion,
    }

    impl<'a> MmioBank<'a> {
        pub fn new(mmio: &'a MmioRegion) -> Self {
            Self { mmio }
        }
    }

    impl RegBank for MmioBank<'_> {
        fn read32(&self, offset: u64) -> u32 {
            // SAFETY: the driver owns BAR0 exclusively; the caller
            // guarantees `offset` is a valid device register.
            unsafe { self.mmio.read32(offset) }
        }
        fn write32(&self, offset: u64, value: u32) {
            // SAFETY: same as above.
            unsafe { self.mmio.write32(offset, value) }
        }
        fn delay_ms(&self, ms: u64) {
            // Pure delay, mirroring bring-up's reset settle.
            narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(ms));
        }
    }

    /// The `nv_txrx_reset` dance (bring-up step 1): raise RESET,
    /// flush-by-read, settle 2 ms, lower by writing BIT2 |
    /// txrxctl_bits, flush-by-read.
    fn txrx_reset(bank: &impl RegBank, txrxctl_bits: u32) {
        bank.write32(
            REG_TX_RX_CONTROL,
            TXRXCTL_BIT2 | TXRXCTL_RESET | txrxctl_bits,
        );
        let _ = bank.read32(REG_TX_RX_CONTROL);
        bank.delay_ms(2);
        bank.write32(REG_TX_RX_CONTROL, TXRXCTL_BIT2 | txrxctl_bits);
        let _ = bank.read32(REG_TX_RX_CONTROL);
    }

    /// Suspend register program: mask interrupts, acknowledge
    /// pending causes, stop the RX/TX paths, drain in-flight DMA
    /// with the `nv_txrx_reset` dance.
    pub fn suspend_plan(bank: &impl RegBank, txrxctl_bits: u32) {
        bank.write32(REG_IRQ_MASK, 0);
        bank.write32(REG_IRQ_STATUS, 0xFFFF_FFFF);
        bank.write32(REG_RCV_CTL, 0);
        bank.write32(REG_XMIT_CTL, 0);
        txrx_reset(bank, txrxctl_bits);
    }

    /// Resume register program: re-enable the RX/TX paths.
    pub fn resume_plan(bank: &impl RegBank) {
        bank.write32(REG_RCV_CTL, RCV_CTL_RX_PATH_EN | RCV_CTL_START);
        bank.write32(REG_XMIT_CTL, XMIT_CTL_TX_PATH_EN | XMIT_CTL_START);
    }

    #[cfg(any(test, feature = "builtin"))]
    mod tests {
        use super::*;
        use narf_kernel_test::{kernel_test_in, TestResult};

        /// In-memory register bank for the PM fixtures: 1 KiB of
        /// BAR0 window, covering IRQ_STATUS/MASK (0x00/0x04),
        /// XMIT_CTL (0x84), RCV_CTL (0x94) and TX_RX_CONTROL
        /// (0x144). Records the settle delays.
        struct FakeBank {
            regs: core::cell::RefCell<alloc::vec::Vec<u32>>,
            delays_ms: core::cell::RefCell<alloc::vec::Vec<u64>>,
        }

        impl FakeBank {
            fn new() -> Self {
                Self {
                    regs: core::cell::RefCell::new(alloc::vec![0u32; 0x400 / 4]),
                    delays_ms: core::cell::RefCell::new(alloc::vec::Vec::new()),
                }
            }
            fn get(&self, offset: u64) -> u32 {
                *self.regs.borrow().get((offset / 4) as usize).unwrap_or(&0)
            }
        }

        impl RegBank for FakeBank {
            fn read32(&self, offset: u64) -> u32 {
                self.get(offset)
            }
            fn write32(&self, offset: u64, value: u32) {
                if let Some(slot) = self.regs.borrow_mut().get_mut((offset / 4) as usize) {
                    *slot = value;
                }
            }
            fn delay_ms(&self, ms: u64) {
                self.delays_ms.borrow_mut().push(ms);
            }
        }

        fn smoke_forcedeth_pm_suspend_stops_paths() -> TestResult {
            let bank = FakeBank::new();
            // Bring-up state: paths enabled, interrupts armed.
            bank.write32(REG_RCV_CTL, RCV_CTL_RX_PATH_EN | RCV_CTL_START);
            bank.write32(REG_XMIT_CTL, XMIT_CTL_TX_PATH_EN | XMIT_CTL_START);
            bank.write32(REG_IRQ_MASK, super::super::IRQMASK_THROUGHPUT);
            suspend_plan(&bank, super::super::TXRXCTL_DESC_2);
            if bank.read32(REG_RCV_CTL) != 0 || bank.read32(REG_XMIT_CTL) != 0 {
                return TestResult::Fail("forcedeth suspend did not stop the RX/TX paths");
            }
            if bank.read32(REG_IRQ_MASK) != 0 || bank.read32(REG_IRQ_STATUS) != 0xFFFF_FFFF {
                return TestResult::Fail("forcedeth suspend did not mask/ack interrupts");
            }
            // The reset dance ran: RESET raised, 2 ms settle, lowered.
            if bank.read32(REG_TX_RX_CONTROL) != TXRXCTL_BIT2 | super::super::TXRXCTL_DESC_2 {
                return TestResult::Fail("forcedeth suspend left TXRXCTL in the reset state");
            }
            if *bank.delays_ms.borrow() != [2u64] {
                return TestResult::Fail("forcedeth suspend did not run the 2 ms reset settle");
            }
            TestResult::Pass
        }
        kernel_test_in!(
            "drivers/net/forcedeth",
            smoke_forcedeth_pm_suspend_stops_paths
        );

        fn smoke_forcedeth_pm_resume_restores_paths() -> TestResult {
            let bank = FakeBank::new();
            bank.write32(REG_RCV_CTL, RCV_CTL_RX_PATH_EN | RCV_CTL_START);
            bank.write32(REG_XMIT_CTL, XMIT_CTL_TX_PATH_EN | XMIT_CTL_START);
            suspend_plan(&bank, super::super::TXRXCTL_DESC_2);
            resume_plan(&bank);
            if bank.read32(REG_RCV_CTL) != RCV_CTL_RX_PATH_EN | RCV_CTL_START {
                return TestResult::Fail("forcedeth resume did not re-enable the RX path");
            }
            if bank.read32(REG_XMIT_CTL) != XMIT_CTL_TX_PATH_EN | XMIT_CTL_START {
                return TestResult::Fail("forcedeth resume did not re-enable the TX path");
            }
            // Polled device: the mask stays as suspend left it.
            if bank.read32(REG_IRQ_MASK) != 0 {
                return TestResult::Fail("forcedeth resume armed interrupts on a polled device");
            }
            // Suspend → resume → suspend is stable.
            suspend_plan(&bank, super::super::TXRXCTL_DESC_2);
            if bank.read32(REG_RCV_CTL) != 0 || bank.read32(REG_XMIT_CTL) != 0 {
                return TestResult::Fail("forcedeth second suspend drifted from the first");
            }
            TestResult::Pass
        }
        kernel_test_in!(
            "drivers/net/forcedeth",
            smoke_forcedeth_pm_resume_restores_paths
        );
    }
}

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

// TX checksum / TSO offload bits. Source: forcedeth.c NV_TX2_*.
pub const NV_TX2_TSO: u32 = 1 << 28;
pub const NV_TX2_TSO_SHIFT: u32 = 14;
pub const NV_TX2_CHECKSUM_L3: u32 = 1 << 27;
pub const NV_TX2_CHECKSUM_L4: u32 = 1 << 26;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    Fail,
    Ok,
}

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

/// TX watchdog timeout (Linux `dev->watchdog_timeo` is 5 s by
/// default, and igc's supervisor uses the same 5 s): a TX
/// descriptor posted longer ago than this with VALID still set is
/// a wedged ring, not congestion.
const TX_TIMEOUT_NS: u64 = 5_000_000_000;

/// True when any posted TX descriptor has waited longer than
/// `timeout` cycles with VALID still set — the ring is wedged (igc
/// `Queue::stalled` shape, per-slot so a later post cannot mask
/// an older stuck one). Factored pure so the fixture pins the
/// decision the watchdog uses.
fn tx_stalled(posted_at: &[u64; RING_LEN], now: u64, timeout: u64) -> bool {
    posted_at
        .iter()
        .any(|&posted| posted != 0 && now.saturating_sub(posted) > timeout)
}

/// Clear a slot's post time only if it still holds the stamp this
/// post recorded: a later post to the same slot (after wraparound)
/// must not have its stamp wiped by the earlier post's completion.
fn tx_note_completed(posted_at: &mut [u64; RING_LEN], slot: usize, stamped: u64) {
    if posted_at[slot] == stamped {
        posted_at[slot] = 0;
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    /// A reset did not complete inside its deadline: either the
    /// `TxRxControl.IDLE` bit never went high, or the `MacReset`
    /// self-clear never landed.
    ResetTimeout,
    /// MII transaction never cleared the INUSE bit.
    MiiTimeout,
    /// MII transaction returned the ERROR latch.
    MiiError,
    /// Frame outside [1, 1518].
    FrameTooLong,
    /// The device is suspended for system suspend (issue #793):
    /// the datapath gates refuse TX and RX while suspended.
    Suspended,
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
pub struct Desc {
    pub buf: u32,
    pub flaglen: u32,
}
const _: () = assert!(core::mem::size_of::<Desc>() == 8);

impl Desc {
    pub fn tx_with_csum(buf: u32, len: u16) -> Self {
        Desc {
            buf,
            flaglen: TXD_VALID
                | TXD_LASTPACKET
                | NV_TX2_CHECKSUM_L3
                | NV_TX2_CHECKSUM_L4
                | (len as u32 & DESC_LEN_MASK_V2),
        }
    }
    pub fn tx_with_tso(buf: u32, len: u16, mss: u16) -> Self {
        // NV_TX2_CHECKSUM_L3/L4 are NOT set when TSO is active — they are
        // in an else-branch in Linux forcedeth.c:2335.  MSS occupies
        // bits[27:14]; CHECKSUM_L3 is bit 27 — setting both corrupts the
        // MSS field on the decode side.
        Desc {
            buf,
            flaglen: TXD_VALID
                | TXD_LASTPACKET
                | NV_TX2_TSO
                | ((mss as u32) << NV_TX2_TSO_SHIFT)
                | (len as u32 & DESC_LEN_MASK_V2),
        }
    }
    pub fn rx_csum_result(&self) -> RxCsumResult {
        if self.flaglen & RXD_ERROR != 0 {
            RxCsumResult::Fail
        } else {
            RxCsumResult::Ok
        }
    }
}

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
    /// Cycle counter at which each TX slot was posted (`0` = no
    /// descriptor outstanding). The watchdog treats an aged entry
    /// as a wedged ring. Stamped by `transmit` after the kick,
    /// cleared when the slot's VALID bit clears.
    tx_posted_at: IrqSafeSpinLock<[u64; RING_LEN]>,
    /// TX stall recoveries (Linux `tx_timeout_count`): incremented
    /// by the watchdog supervisor when it fires `recover()` on a
    /// ring stalled 5 s, mirroring igc's `tx_timeouts`.
    tx_timeouts: AtomicU64,
    /// Controller resets performed by [`ForcedethNic::recover`].
    tx_resets: AtomicU64,
    /// Set while [`ForcedethNic::recover`] owns the reset sequence:
    /// TX posts fail fast instead of racing the ring reprogram (a
    /// post landing mid-reset could be zeroed with the stale ring
    /// or never rung).
    recovering: AtomicBool,
    /// TX ring epoch, advanced by [`ForcedethNic::recover`] on
    /// every recovery. A `transmit` whose VALID poll straddles a
    /// reset sees VALID clear because the reset zeroed the ring —
    /// not because its frame went out. The epoch distinguishes a
    /// real completion from a reset, so that caller reports
    /// `TxTimeout` instead of a success it did not earn.
    tx_epoch: AtomicU64,
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
    /// WoL enable (issue #792): the stored `wolenabled` flag from
    /// Linux `nv_set_wol`.
    wol_enabled: AtomicBool,
    /// True while the device is suspended (datapath gate).
    /// Set by `suspend`, cleared by `resume`: the datapath gates
    /// refuse TX and RX while this is set (issue #793).
    suspended: AtomicBool,
    /// PCI address of the function this instance drives. Probe
    /// refuses a second bind of the same address (issue #795): two
    /// `ForcedethNic`s for one chip would drive one set of rings.
    pub addr: narf_bus::BusAddr,
    /// Interface name `publish_netdev_with_context` assigned this
    /// instance (`eth%d`). Per-instance (i40e/igc pattern): the old
    /// module-level `FORCEDETH_IFNAME` static could only name one NIC.
    ifname: crate::publish::IfName,

    // IPC integration
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: The only non-Send/Sync members are the raw MMIO/DMA pointers
// inside `mmio`, `tx_ring`, `rx_ring`, and the per-slot pools. Those
// point at device BAR0 / DMA-coherent memory that is not bound to any
// particular thread, so they are valid to touch from any CPU. All
// interior-mutable driver state (`tx_head`, `rx_head`, the IPC rings) is
// guarded by `IrqSafeSpinLock`, which serialises concurrent access, so
// sharing `&ForcedethNic` across threads cannot create a data race.
unsafe impl Send for ForcedethNic {}
// SAFETY: see the `Send` impl above — every field that is mutated through
// `&self` lives behind an `IrqSafeSpinLock`, so `&ForcedethNic` is sound
// to share between threads.
unsafe impl Sync for ForcedethNic {}

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
    ) -> Result<Arc<Self>, NicError> {
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
            mmio.write32(
                REG_TX_RX_CONTROL,
                TXRXCTL_BIT2 | TXRXCTL_RESET | txrxctl_bits,
            );
            // PCI flush-by-read (the chip orders ops by ack-back of
            // the write — Linux does this via `pci_push` which is a
            // `readl` of any post-decoded register).
            let _ = mmio.read32(REG_TX_RX_CONTROL);
        }
        // Spin briefly. Linux uses a fixed 4 µs `udelay` here and does
        // NOT poll for RESET to self-clear — the reset bit is dropped by
        // the explicit write of 0 below. So we want a pure delay: pass a
        // predicate that never reports "done" and let the call run until
        // the deadline expires, while background pumps still tick.
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(2));
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
                mac_a as u8,
                (mac_a >> 8) as u8,
                (mac_a >> 16) as u8,
                (mac_a >> 24) as u8,
                mac_b as u8,
                (mac_b >> 8) as u8,
            ]
        } else {
            // Reversed-byte-order workaround case. Forcedeth.c also
            // re-writes MacAddrA/B with the corrected layout + sets
            // MAC_ADDR_REV; we do the same so the chip sees a stable
            // MAC after the reset.
            let m = [
                (mac_b >> 8) as u8,
                mac_b as u8,
                (mac_a >> 24) as u8,
                (mac_a >> 16) as u8,
                (mac_a >> 8) as u8,
                mac_a as u8,
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
        let tx_ring =
            alloc_coherent(RING_LEN * 8, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let rx_ring =
            alloc_coherent(RING_LEN * 8, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            rx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            tx_pool.push(alloc_coherent(2048, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?);
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
        let tx_phys = tx_ring.dma_addr().raw();
        let rx_phys = rx_ring.dma_addr().raw();
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
        let rx_ring_phys = rx_ring.dma_addr().raw();
        for (i, slot) in rx_pool.iter().enumerate().take(RING_LEN) {
            let buf_phys = slot.dma_addr().raw();
            let d = Desc {
                buf: buf_phys as u32,
                flaglen: RXD_AVAIL | (RX_BUF_LEN as u32 & DESC_LEN_MASK_V2),
            };
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 8) as u64)
                        .kernel_mut_ptr::<Desc>(),
                    d,
                );
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

        // 11. Wake-on-LAN starts disabled (issue #792): Linux's
        //     probe writes `WakeUpFlags = 0` with `wolenabled = 0`
        //     (`nv_init_nic` only arms it once the flag is set).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(crate::wol::REG_WAKEUP_FLAGS, 0);
        }

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let nic = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            tx_posted_at: IrqSafeSpinLock::new([0; RING_LEN]),
            tx_timeouts: AtomicU64::new(0),
            tx_resets: AtomicU64::new(0),
            recovering: AtomicBool::new(false),
            tx_epoch: AtomicU64::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            phy_addr,
            txrxctl_bits,
            wol_enabled: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            addr: device.addr,
            ifname: crate::publish::IfName::new(),
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn the device's only pump pair — probe spawns none, so the
        // pair fed here is the pair whose halves occupy the ring slots.
        spawn_pumps(nic.clone(), rx_prod, tx_cons);

        // Return the `Arc` directly: unwrapping it back to `Self`
        // (the old `Arc::try_unwrap` tail) always failed — the pump
        // tasks above hold clones, so the refcount is above 1 and
        // probe could never bind even the first NIC. e1000's
        // bring_up documents the same trap (e1000.rs, bring_up
        // step 9 comment).
        Ok(nic)
    }

    /// Transmit a single Ethernet frame, polled. Frame must be in
    /// `[1, 1518]` bytes; padding for runt frames is the chip's job.
    pub fn transmit(&self, frame: &[u8], meta: &TxMeta) -> Result<(), NicError> {
        if self.suspended.load(Ordering::Acquire) {
            return Err(NicError::Suspended);
        }
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
        }
        // Fail fast while recovery owns the reset sequence: a post
        // landing mid-reset could be zeroed with the stale ring.
        // TxRingFull is the honest signal — the ring is not
        // accepting posts right now, and the caller retries.
        if self.recovering.load(Ordering::Acquire) {
            return Err(NicError::TxRingFull);
        }

        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked by
        // FrameTooLong guard.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        let ring_phys = self.tx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 8) as u64;

        // SAFETY: identity-mapped DMA ring page.
        let cur = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 4).kernel_ptr::<u32>())
        };
        if cur & TXD_VALID != 0 {
            return Err(NicError::TxRingFull);
        }

        // Build descriptor — select offload flags from TxMeta.
        let d = if let Some(mss) = meta.tso_mss {
            Desc::tx_with_tso(phys as u32, frame.len() as u16, mss)
        } else if meta.csum_l4.is_some() {
            Desc::tx_with_csum(phys as u32, frame.len() as u16)
        } else {
            Desc {
                buf: phys as u32,
                flaglen: TXD_VALID | TXD_LASTPACKET | (frame.len() as u32 & DESC_LEN_MASK_V2),
            }
        };
        // Per forcedeth.c §"nv_start_xmit_optimized": write buf first,
        // fence, then flip flaglen (VALID + offload bits). The chip
        // sees VALID set only after the buffer pointer has propagated.
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                d.buf,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                d.flaglen,
            );
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

        // Post time for the watchdog (see `tx_stalled`): stamped
        // once the kick has rung, so a descriptor the chip never
        // completes ages from its post, not from entry.
        let stamped = narf_time::now_cycles();
        self.tx_posted_at.lock()[slot] = stamped;
        // TX epoch at post time: if a watchdog recovery resets the
        // ring while this poll runs, VALID reads clear because the
        // reset zeroed the descriptor — the epoch check below keeps
        // that from reporting as a completion.
        let epoch = self.tx_epoch.load(Ordering::Acquire);

        // Poll for VALID → 0. The chip clears VALID once the frame
        // has been DMA'd to its TX FIFO. 250 ms wall-clock budget.
        let owned = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA ring.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 4).kernel_ptr::<u32>()) } & TXD_VALID == 0,
            narf_time::Deadline::after_ms(250),
        );
        if !owned {
            return Err(NicError::TxTimeout);
        }
        // A reset during the poll zeroes the ring, so VALID reads
        // clear even though this frame never went out: the epoch
        // distinguishes a real completion from a reset.
        if epoch != self.tx_epoch.load(Ordering::Acquire) {
            return Err(NicError::TxTimeout);
        }
        // VALID cleared: the descriptor completed, so its post time
        // is void (conditional clear — a later post to this slot
        // must keep its own stamp).
        {
            let mut posted = self.tx_posted_at.lock();
            tx_note_completed(&mut posted, slot, stamped);
        }
        // (no scratch drop — buffer is persistent in tx_pool)
        Ok(())
    }

    /// Pop one received frame off the RX ring. Returns `Some(buf)`
    /// when a descriptor's AVAIL bit reads 0 (chip handed it back)
    /// and `None` when the head is still chip-owned — or while the
    /// device is suspended.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        if self.suspended.load(Ordering::Acquire) {
            return None;
        }
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 8) as u64;

        // SAFETY: identity-mapped DMA ring.
        let flaglen = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr + 4).kernel_ptr::<u32>())
        };
        if flaglen & RXD_AVAIL != 0 {
            return None;
        }

        let len = (flaglen & DESC_LEN_MASK_V2) as usize;
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flaglen & RXD_DESCRIPTOR_VALID != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            for i in 0..copy_len {
                // SAFETY: `buf_phys` is the identity-mapped physical base
                // of this slot's RX_BUF_LEN-byte DMA buffer; `i < copy_len
                // <= RX_BUF_LEN`, so `buf_phys + i` stays inside that
                // buffer and is a valid, aligned `u8` address to read.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                out.push(unsafe {
                    core::ptr::read_volatile(self.rx_pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }

        // Re-arm: hand the descriptor back to the chip.
        let d = Desc {
            buf: buf_phys as u32,
            flaglen: RXD_AVAIL | (RX_BUF_LEN as u32 & DESC_LEN_MASK_V2),
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<Desc>(),
                d,
            );
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some(out)
    }

    /// Live carrier read: the same BMSR double-read
    /// [`Self::refresh_link_state`] performs, without the `&mut`
    /// store. The RX pump holds only an `Arc<ForcedethNic>`, so the
    /// publication path (issue #791) samples through this.
    ///
    /// A failed MII transaction reports the last-known state
    /// (`self.link_up`), not link-down: a transient bus error is
    /// not a carrier loss, and reporting down would flap the
    /// published carrier and suppress the TX watchdog's recovery
    /// on a genuinely wedged ring. (A fixture's plain MMIO backing
    /// page cannot emulate the chip's `MIIStatus` write-to-clear,
    /// so its MII reads always fail with `MiiError` — the
    /// fallback is what lets the watchdog fixture see link-up.)
    pub fn live_link_up(&self) -> bool {
        if self.phy_addr >= 32 {
            return false;
        }
        // sticky-low: double-read, as in refresh_link_state.
        let _ = mii_rw(&self.mmio, self.phy_addr, MII_BMSR, None);
        match mii_rw(&self.mmio, self.phy_addr, MII_BMSR, None) {
            Ok(bmsr) => (bmsr as u16) & BMSR_LINK_UP != 0,
            Err(_) => self.link_up,
        }
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

    // ── Wake-on-LAN (issue #792) ────────────────────────────────────

    /// Set the WoL enable (Linux `nv_set_wol` semantics, infallible
    /// like Linux: it returns 0 always). Only `WAKE_MAGIC` is
    /// honoured; any other non-zero word leaves the stored enable
    /// unchanged. The `WakeUpFlags` register is programmed live from
    /// the stored enable — see `wol.rs` for the one deliberate
    /// deviation from Linux's write here.
    pub fn set_wol(&self, wolopts: u32) {
        let enabled = crate::wol::set_wol(wolopts, self.wol_enabled.load(Ordering::Acquire));
        self.wol_enabled.store(enabled, Ordering::Release);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(
                crate::wol::REG_WAKEUP_FLAGS,
                crate::wol::wakeup_flags(enabled),
            );
        }
    }

    /// Read the WoL surface (Linux `nv_get_wol`):
    /// `(supported, wolopts)`.
    pub fn get_wol(&self) -> (u32, u32) {
        (
            crate::wol::wol_supported_opts(),
            crate::wol::wol_opts(self.wol_enabled.load(Ordering::Acquire)),
        )
    }

    /// Suspend the device for system sleep (Linux `nv_close` WoL
    /// block, issue #792) + the #793 register plan: mask IRQs, stop
    /// the RX/TX paths and drain in-flight DMA with the
    /// `nv_txrx_reset` dance, then arm the receiver for wake
    /// filtering when WoL is enabled (or, by the Linux default,
    /// whenever the PHY is left powered), and publish link down.
    /// The WoL program runs after the path stop, so on the live path
    /// (PHY left powered) it re-arms RX with the wake filter — the
    /// stop is a drain, not a final state — while TX stays stopped.
    /// Idempotent: a second suspend is a no-op success. The PCI PME
    /// enable is the platform power layer's job
    /// (`narf_bus::pci_pme`); this programs only the device-side
    /// wake filtering.
    pub fn suspend(&self) -> Result<(), NicError> {
        if self.suspended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        // Issue #793: stop the paths + drain first (this also masks
        // IRQs and acknowledges pending causes).
        pm::suspend_plan(&pm::MmioBank::new(&self.mmio), self.txrxctl_bits);
        // NARF has no `phy_power_down` module parameter, so the live
        // path always takes Linux's default (`phy_power_down = 0`):
        // the receiver stays armed and the PHY stays up.
        let program = crate::wol::suspend_program(self.wol_enabled.load(Ordering::Acquire), false);
        let mut bank = crate::wol::MmioRegBank(&self.mmio);
        crate::wol::apply_suspend(&mut bank, &program);
        if program.power_down_phy && self.phy_addr < 32 {
            // Linux read-modify-writes BMCR with PDOWN. Unreachable
            // on the live path (the default program never sets the
            // flag); kept so the `phy_power_down = 1` program stays
            // executable, not just fixture-tested.
            if let Ok(bmcr) = mii_rw(&self.mmio, self.phy_addr, MII_BMCR, None) {
                let _ = mii_rw(
                    &self.mmio,
                    self.phy_addr,
                    MII_BMCR,
                    Some(bmcr | crate::wol::BMCR_PDOWN as u32),
                );
            }
        }
        crate::publish::publish_link(self.ifname(), crate::publish::LinkSample::DOWN);
        Ok(())
    }

    /// Resume a suspended device (Linux `nv_resume` → `nv_init_nic`
    /// order, adapted, issue #792): re-assert `WakeUpFlags` from the
    /// stored enable, restore the bring-up datapath words, restart
    /// PHY autoneg out of any power-down, and republish link.
    /// Resuming a running device is a no-op success. The rings are
    /// retained across the sleep (no ring rebuild, unlike Linux's
    /// full `nv_open` on resume — the `PowerState2` clock gate is
    /// likewise not modeled; see `wol.rs`).
    ///
    /// Issue #793: the `pm::resume_plan` (re-enable the RX/TX
    /// paths) is subsumed — the bring-up words restored here are
    /// the same `RX_PATH_EN | START` / `TX_PATH_EN | START` words
    /// (`0x01000001`) — so the live path does not call it; the plan
    /// stays fixture-tested in `mod pm`. The autoneg restart is
    /// main's direct BMCR write (not the branch's
    /// read-modify-write): the direct write clears a latched PDOWN,
    /// which is what wakes a powered-down PHY.
    pub fn resume(&self) -> Result<(), NicError> {
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let words = crate::wol::resume_words();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(
                crate::wol::REG_WAKEUP_FLAGS,
                crate::wol::wakeup_flags(self.wol_enabled.load(Ordering::Acquire)),
            );
            self.mmio
                .write32(crate::wol::REG_PACKET_FILTER, words.packet_filter);
            self.mmio.write32(crate::wol::REG_RCV_CTL, words.rcv_ctl);
            self.mmio.write32(crate::wol::REG_XMIT_CTL, words.xmit_ctl);
        }
        // Restart autoneg out of a power-down (the igb-resume
        // shape); a PHY that was never powered down just restarts
        // autoneg, which is what Linux's resume-time `phy_reset`
        // does anyway.
        if self.phy_addr < 32 {
            let _ = mii_rw(
                &self.mmio,
                self.phy_addr,
                MII_BMCR,
                Some((BMCR_AUTONEG_EN | BMCR_AUTONEG_RESTART) as u32),
            );
        }
        self.suspended.store(false, Ordering::Release);
        crate::publish::publish_link(
            self.ifname(),
            crate::publish::LinkSample::carrier_only(self.live_link_up()),
        );
        Ok(())
    }

    /// TX stall recoveries (Linux `tx_timeout_count`).
    pub fn tx_timeouts(&self) -> u64 {
        self.tx_timeouts.load(Ordering::Relaxed)
    }

    /// Controller resets performed by [`ForcedethNic::recover`].
    pub fn tx_resets(&self) -> u64 {
        self.tx_resets.load(Ordering::Relaxed)
    }

    /// One watchdog pass, synchronously (the fixture): the core
    /// watchdog's check, then `ndo_tx_timeout` if it fired. Returns
    /// true when recovery fired and succeeded.
    fn check_tx_watchdog_at(&self, now: u64) -> bool {
        use narf_net::watchdog::NetdevWatchdog;
        if !self.tx_timed_out(now) {
            return false;
        }
        self.tx_timeouts.fetch_add(1, Ordering::Relaxed);
        self.recover().is_ok()
    }

    /// TX-timeout recovery (Linux `nv_tx_timeout` + `nv_reset`
    /// shape): stop the TX/RX paths, chip-wide MAC reset, reset the
    /// TX/RX state machines, and reprogram the rings and filters
    /// from the bring-up values. The TX cursor is reset —
    /// descriptors posted before the reset will never complete —
    /// and the RX descriptors are re-primed from the pool. A reset
    /// that never self-clears reports `ResetTimeout` and leaves the
    /// device stopped; a concurrent recovery reports `TxRingFull`
    /// without touching the device. The PHY is not re-initialised:
    /// the reset is a MAC-block reset and does not touch the MII
    /// glue or the PHY.
    pub fn recover(&self) -> Result<(), NicError> {
        if self.recovering.swap(true, Ordering::AcqRel) {
            return Err(NicError::TxRingFull);
        }
        // Advance the TX epoch before the reset: any `transmit`
        // whose VALID poll straddles the reset sees VALID clear
        // because the reset zeroed the ring, not because its frame
        // went out — the epoch lets it report `TxTimeout` instead
        // of a success it did not earn.
        self.tx_epoch.fetch_add(1, Ordering::Release);
        let result = self.recover_inner();
        self.recovering.store(false, Ordering::Release);
        if result.is_ok() {
            self.tx_resets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn recover_inner(&self) -> Result<(), NicError> {
        // 1. Mask interrupts, clear any latched causes, and stop
        // the TX/RX paths.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IRQ_MASK, 0);
            self.mmio.write32(REG_IRQ_STATUS, 0xFFFFFFFF);
            self.mmio.write32(REG_XMIT_CTL, 0);
            self.mmio.write32(REG_RCV_CTL, 0);
        }
        // Poll the TX/RX BUSY bits to 0 ("polled at stop" per the
        // register table). A path that never idles is itself the
        // wedge; the MAC reset below is what un-wedges it, so the
        // result is observed but does not fail the recovery.
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(REG_XMIT_STATUS) } & XMIT_STATUS_BUSY == 0
                // SAFETY: `REG_RCV_STATUS` (0x098) is a 4-byte-aligned status
                // register inside the mapped BAR, so `offset + 4 <= len`
                // holds; the volatile read only samples the RX BUSY bit
                // and has no clear-on-read side effect.
                && unsafe { self.mmio.read32(REG_RCV_STATUS) } & RCV_STATUS_BUSY == 0,
            narf_time::Deadline::after_ms(100),
        );
        // 2. Chip-wide MAC reset. `MacReset` self-clears once the
        // MAC block has re-initialised; 100 ms is the wedge
        // threshold (same bound as the other families' resets).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_MAC_RESET, MAC_RESET_ASSERT);
        }
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(REG_MAC_RESET) } & MAC_RESET_ASSERT == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(NicError::ResetTimeout);
        }
        // Re-mask after the reset: the reset may have restored the
        // power-on mask, and Stage-2 stays polled.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_IRQ_MASK, 0);
            self.mmio.write32(REG_IRQ_STATUS, 0xFFFFFFFF);
        }
        // 3. Reset the TX/RX state machines (bring-up step 1):
        // raise RESET | BIT2 | txrxctl_bits, push the write, wait
        // 2 ms, then lower RESET.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(
                REG_TX_RX_CONTROL,
                TXRXCTL_BIT2 | TXRXCTL_RESET | self.txrxctl_bits,
            );
            let _ = self.mmio.read32(REG_TX_RX_CONTROL);
        }
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(2));
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write32(REG_TX_RX_CONTROL, TXRXCTL_BIT2 | self.txrxctl_bits);
            let _ = self.mmio.read32(REG_TX_RX_CONTROL);
        }
        // 4. Reprogram the MII clock divider (bring-up step 4) and
        // the station address. The MAC reset may have cleared the
        // address registers, so rewrite the decoded MAC in natural
        // order with MAC_ADDR_REV latched — the post-bring-up
        // layout in both the correct-order and the reversed-order
        // cases, so the write is idempotent.
        let mac_a = (self.mac[0] as u32)
            | ((self.mac[1] as u32) << 8)
            | ((self.mac[2] as u32) << 16)
            | ((self.mac[3] as u32) << 24);
        let mac_b = (self.mac[4] as u32) | ((self.mac[5] as u32) << 8);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_MII_SPEED, MIISPEED_DEFAULT);
            self.mmio.write32(REG_MAC_ADDR_A, mac_a);
            self.mmio.write32(REG_MAC_ADDR_B, mac_b);
            let txpoll = self.mmio.read32(REG_TRANSMIT_POLL);
            self.mmio
                .write32(REG_TRANSMIT_POLL, txpoll | TRANSMIT_POLL_MAC_ADDR_REV);
        }
        // 5. Zero the TX ring (a stale VALID bit would make a fresh
        // post look ring-full) and reprogram the ring bases +
        // sizes (bring-up step 7).
        // SAFETY: the TX ring is a coherent DMA buffer of exactly
        // `RING_LEN * 8` bytes.
        unsafe {
            core::ptr::write_bytes(self.tx_ring.cpu_mut_ptr_at::<u8>(0), 0, RING_LEN * 8);
        }
        let tx_phys = self.tx_ring.dma_addr().raw();
        let rx_phys = self.rx_ring.dma_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TX_RING_PHYS, tx_phys as u32);
            self.mmio.write32(REG_RX_RING_PHYS, rx_phys as u32);
            self.mmio
                .write32(REG_TX_RING_PHYS_HIGH, (tx_phys >> 32) as u32);
            self.mmio
                .write32(REG_RX_RING_PHYS_HIGH, (rx_phys >> 32) as u32);
            self.mmio.write32(
                REG_RING_SIZES,
                ((RING_LEN as u32 - 1) << RINGSZ_TXSHIFT)
                    | ((RING_LEN as u32 - 1) << RINGSZ_RXSHIFT),
            );
        }
        // 6. Re-prime the RX descriptors from the pool (bring-up
        // step 8).
        let rx_ring_phys = self.rx_ring.dma_addr().raw();
        for (i, slot) in self.rx_pool.iter().enumerate().take(RING_LEN) {
            let buf_phys = slot.dma_addr().raw();
            let d = Desc {
                buf: buf_phys as u32,
                flaglen: RXD_AVAIL | (RX_BUF_LEN as u32 & DESC_LEN_MASK_V2),
            };
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 8) as u64)
                        .kernel_mut_ptr::<Desc>(),
                    d,
                );
            }
        }
        // 7. Restore the packet filter and re-enable the receive +
        // transmit paths (bring-up step 10).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write32(REG_PACKET_FILTER, PFF_ALWAYS | PFF_MYADDR);
            self.mmio
                .write32(REG_RCV_CTL, RCV_CTL_RX_PATH_EN | RCV_CTL_START);
            self.mmio
                .write32(REG_XMIT_CTL, XMIT_CTL_TX_PATH_EN | XMIT_CTL_START);
        }
        // 8. Reset the software cursors now that the rings are
        // fresh, and republish link from the live PHY state.
        *self.tx_head.lock() = 0;
        *self.rx_head.lock() = 0;
        self.tx_posted_at.lock().fill(0);
        crate::publish::publish_link(
            self.ifname(),
            crate::publish::LinkSample::carrier_only(self.live_link_up()),
        );
        Ok(())
    }
}

// ── MII transaction helper ──────────────────────────────────────────

/// Read or write a single PHY register through the chip's MII glue.
/// `value = None` performs a read, `value = Some(v)` performs a write.
/// Returns the read-back data (or `Ok(0)` after a write). Matches the
/// shape of forcedeth.c's `mii_rw`.
fn mii_rw(mmio: &MmioRegion, addr: u8, reg: u32, value: Option<u32>) -> Result<u32, NicError> {
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

impl ForcedethNic {
    /// This instance's published interface name (`eth%d`), or `""`
    /// before probe publishes it. Per-instance state (i40e/igc
    /// pattern); the pumps and the registry adapter read the name
    /// off the device they serve, never a module-level static.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }
}

impl narf_power::device_pm::DevicePmOps for ForcedethNic {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.suspend()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.resume()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
}

// ── Driver-match registration ───────────────────────────────────────

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`forcedeth_send_frame`] — the i40e `CONTROLLERS` pattern, so a
/// second nForce NIC on the same machine probes, binds, and carries
/// traffic instead of being dropped by a singleton slot (issue
/// #795). The vec never shrinks, so a live controller's cookie
/// stays valid for the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<ForcedethNic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// `SendCtxFn` registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through
/// `ForcedethNic::transmit`; the cookie is the controller's index in
/// `CONTROLLERS`. The `Arc` is cloned out rather than holding the
/// IRQ-masking `CONTROLLERS` lock across `transmit` (same reasoning
/// as e1000's send path).
fn forcedeth_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = controller(cookie as usize).ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Probe entry — installed via `bus::register_pci_driver`. A second
/// probe of the SAME function is a no-op success (the old idempotent
/// behaviour): the bus re-walks devices, and rebuilding a second
/// `ForcedethNic` for the same silicon would let two instances drive
/// one chip's rings. A second FUNCTION binds as a new instance
/// instead of being dropped (issue #795).
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLERS.lock().iter().any(|c| c.addr == device.addr) {
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

    // SAFETY: `bring_up` requires exclusive ownership of the device's
    // BAR/config windows for the duration of init. This is the probe
    // entry point for `device`/`cap`: nothing else has touched the BARs
    // yet, and we hold the `Write` capability `cap`, so the contract is
    // satisfied.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let nic = match unsafe { ForcedethNic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    // Retain before any ring DMA address reaches the device; the
    // index is this instance's send-path cookie (see `CONTROLLERS`).
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(nic.clone());
        g.len() - 1
    };

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Publish to the kernel-side stack (issue #784): a dynamic `eth%d`
    // name + carrier metadata via the shared helper, keyed by the
    // `CONTROLLERS` index so each port's send path resolves to its
    // own NIC (i40e pattern). This wires the LinkChg re-evaluation
    // the bring-up comment deferred: the datapath's interrupts are
    // masked in this stage, so the polled RX pump (spawned by
    // `bring_up`) is the observer that republishes on a transition
    // (issue #791). The frame-ring registration below stays.
    let name = crate::publish::publish_netdev_with_context(
        nic.mac,
        index as u64,
        forcedeth_send_frame,
        crate::publish::LinkSample::carrier_only(nic.live_link_up()),
    );
    nic.ifname.set(name);

    // Device-PM registration (#793): system suspend fans out
    // through `ForcedethNic::suspend` / `ForcedethNic::resume` via
    // the `DevicePmOps` impl below. The registry is idempotent on
    // the interface name. There is no forcedeth detach path to
    // withdraw the entry from yet — the CONTROLLER slot is never
    // drained either, so the entry lives as long as the device does.
    narf_power::device_pm::register_device_pm_ops(nic.ifname(), nic.clone());

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(
            &auth,
            ForcedethHwNic {
                nic: nic.clone(),
                name: "eth6",
            },
        );
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
    device: Arc<ForcedethNic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        forcedeth_rx_pump(d1, rx_prod).await;
    });

    let d2 = device.clone();
    narf_scheduler::spawn(async move {
        forcedeth_tx_pump(d2, tx_cons).await;
    });

    // `dev_watchdog`: a timer every `watchdog_timeo` (5 s) that queues
    // the reset when a transmit is stuck; it stops with the device.
    let weak: alloc::sync::Weak<dyn narf_net::watchdog::NetdevWatchdog> =
        Arc::downgrade(&device) as _;
    narf_net::watchdog::DevWatchdog::start_for_device(weak, TX_TIMEOUT_NS);
}

async fn forcedeth_rx_pump(device: Arc<ForcedethNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Carrier refresh (issue #791): see the probe comment — with IRQ
    // delivery masked in this stage, this polled pump is the family's
    // link observer; a BMSR transition republishes the metadata.
    let mut last_up = device.live_link_up();
    loop {
        let up = device.live_link_up();
        if up != last_up {
            last_up = up;
            crate::publish::publish_link(
                device.ifname(),
                crate::publish::LinkSample::carrier_only(up),
            );
        }
        if let Some(pkt) = device.receive() {
            let dma_buf =
                alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
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
                    let _ = rx_prod.try_send(mirror);
                },
            );
        }
        narf_scheduler::yield_now().await;
    }
}

async fn forcedeth_tx_pump(device: Arc<ForcedethNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
    }
}

/// The core transmit watchdog's view of the device (`dev_watchdog` +
/// `nv_tx_timeout`).
impl narf_net::watchdog::NetdevWatchdog for ForcedethNic {
    /// A TX descriptor waited past `TX_TIMEOUT_NS` with link up and no
    /// recovery in progress.
    fn tx_timed_out(&self, now: u64) -> bool {
        if self.recovering.load(Ordering::Acquire) {
            return false;
        }
        if !self.live_link_up() {
            return false;
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        tx_stalled(&self.tx_posted_at.lock(), now, timeout)
    }

    /// Count the timeout and reset the transmit path (task context).
    fn tx_timeout(&self) {
        self.tx_timeouts.fetch_add(1, Ordering::Relaxed);
        let _ = self.recover();
    }
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

/// One probed port, as the net stack sees it.
///
/// This owns its `Arc<ForcedethNic>` rather than looking the
/// controller up in a module-level static. That is what makes
/// multiple ports work: `Interface::rx_ring` / `tx_ring` return
/// references borrowed from `&self`, so an interface with no storage
/// of its own has to hand back a `static` — and every instance would
/// then share one pair of rings, with the second port's frames
/// landing in the first port's queue (i40e's `I40eNicIface`
/// pattern).
#[derive(Debug)]
pub struct ForcedethHwNic {
    /// This port's controller; the rings are borrowed out of it.
    nic: Arc<ForcedethNic>,
    /// Pre-publish fallback name, used by [`narf_net::Interface::name`]
    /// before probe publishes the dynamic `eth%d` name.
    name: &'static str,
}

impl narf_net::Interface for ForcedethHwNic {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // old frame-ring name before probe gets that far.
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
        1500
    }
    fn link_up(&self) -> bool {
        self.nic.link_up
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

impl crate::HwNic for ForcedethHwNic {
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
        1500
    }
    fn link_up(&self) -> bool {
        self.nic.link_up
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::NvidiaForcedeth
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

/// Number of probed controllers (issue #795).
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
pub fn controller(index: usize) -> Option<Arc<ForcedethNic>> {
    CONTROLLERS.lock().get(index).cloned()
}

/// Test-side accessor: run `f` against the probed controller at
/// `index` (i40e shape).
pub fn with_controller<R>(index: usize, f: impl FnOnce(&ForcedethNic) -> R) -> Option<R> {
    CONTROLLERS.lock().get(index).map(|a| f(a))
}

/// Mutable accessor — used by tests that need to drive PHY state
/// refresh.
pub fn with_controller_mut<R>(index: usize, f: impl FnOnce(&mut ForcedethNic) -> R) -> Option<R> {
    CONTROLLERS
        .lock()
        .get_mut(index)
        .map(|a| f(Arc::get_mut(a).expect("ForcedethNic static has multiple owners")))
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
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
        let must_have: &[u16] = &[NV_DEV_MCP55_1, NV_DEV_MCP73_1, NV_DEV_MCP77_1];
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

    /// Same shape as `smoke_e1000_multi_instance_cookie_dispatch` in
    /// `drivers/net/src/tests.rs` (see its doc comment): one live
    /// instance at cookie 0, no instance at cookie 1, published iface
    /// resolves by name, `send_on` dispatches through cookie 0,
    /// re-probe keeps the same `Arc`, and the registry adapter borrows
    /// the NIC's own rings. The QEMU test VM has no nForce NIC, so
    /// only the no-silicon branch runs in CI; the live branch runs on
    /// real hardware. This also pins the `bring_up` fix: before #795
    /// the probe always failed here because `Arc::try_unwrap` could
    /// never succeed once the pump tasks held clones — `is_probed()`
    /// after probe would have been false.
    fn smoke_forcedeth_multi_instance_cookie_dispatch() -> TestResult {
        use narf_bus::driver_match::__reset_for_test;
        use narf_bus::x86_64::ECAM_DEFAULT_BASE;
        use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
        // SAFETY: ECAM_DEFAULT_BASE is the q35 MMCONFIG window the test harness
        // maps before running; `init` only walks that ECAM region and is safe to
        // call repeatedly (idempotent on re-entry).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
        let devs = devices();
        let has_fe = devs.iter().any(|d| {
            matches!(&d.kind, BusKind::Pcie { .. })
                && d.id.vendor == NV_VENDOR
                && SUPPORTED_DEVICE_IDS.contains(&d.id.device)
        });
        if !has_fe {
            if instance_count() != 0 {
                return TestResult::Fail("instance_count != 0 with no forcedeth silicon");
            }
            if controller(0).is_some() {
                return TestResult::Fail("controller(0) Some with no forcedeth silicon");
            }
            if is_probed() {
                return TestResult::Fail("is_probed with no forcedeth silicon");
            }
            let frame = [0u8; 64];
            if narf_net::iface::send_on("eth999", &frame).is_ok() {
                return TestResult::Fail("send_on resolved a nonexistent iface");
            }
            return TestResult::Pass;
        }
        __reset_for_test();
        register_pci_driver();
        let authority = bootstrap_registry_authority();
        if probe_all_pci(&authority).is_err() {
            return TestResult::Fail("probe_all_pci");
        }
        if !is_probed() {
            return TestResult::Fail("forcedeth not probed");
        }
        if instance_count() != 1 {
            return TestResult::Fail("instance_count != 1 after single-NIC probe");
        }
        let ctrl = match controller(0) {
            Some(c) => c,
            None => return TestResult::Fail("controller(0) None after probe"),
        };
        if controller(1).is_some() {
            return TestResult::Fail("controller(1) Some with one NIC");
        }
        if controller(usize::MAX).is_some() {
            return TestResult::Fail("controller(MAX) Some");
        }
        let name = ctrl.ifname();
        if name.is_empty() {
            return TestResult::Fail("published name empty after probe");
        }
        if narf_net::iface::lookup(name).is_none() {
            return TestResult::Fail("iface not published under its name");
        }
        let mut frame = [0u8; 64];
        frame[..6].fill(0xFF);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        frame[12] = 0xFF;
        frame[13] = 0xFF;
        if narf_net::iface::send_on(name, &frame).is_err() {
            return TestResult::Fail("send_on cookie-0 TX failed");
        }
        let authority = bootstrap_registry_authority();
        let _ = probe_all_pci(&authority);
        let after = match controller(0) {
            Some(c) => c,
            None => return TestResult::Fail("controller(0) vanished across re-probe"),
        };
        if Arc::as_ptr(&after) != Arc::as_ptr(&ctrl) {
            return TestResult::Fail("re-probe replaced controller(0)");
        }
        let ring_ptr =
            narf_net::registry().with_interface(name, |i| i.rx_ring() as *const _ as usize);
        if ring_ptr != Some(&ctrl.rx_ipc_ring as *const _ as usize) {
            return TestResult::Fail("adapter rx_ring is not the NIC's own ring");
        }
        if ctrl.rx_ipc_ring.lock().is_none() {
            return TestResult::Fail("attach took the NIC's RX ring");
        }
        let tx_ptr =
            narf_net::registry().with_interface(name, |i| i.tx_ring() as *const _ as usize);
        if tx_ptr != Some(&ctrl.tx_ipc_ring as *const _ as usize) {
            return TestResult::Fail("adapter tx_ring is not the NIC's own ring");
        }
        if ctrl.tx_ipc_ring.lock().is_none() {
            return TestResult::Fail("attach took the NIC's TX ring");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_multi_instance_cookie_dispatch
    );

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
        if TXRXCTL_DESC_2 != 0x0000_2100 {
            return TestResult::Fail("TXRXCTL_DESC_2 drift");
        }
        if TXRXCTL_DESC_3 != 0x00c0_2200 {
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
        let v =
            ((RING_LEN as u32 - 1) << RINGSZ_TXSHIFT) | ((RING_LEN as u32 - 1) << RINGSZ_RXSHIFT);
        if (v & 0xFFFF) != (RING_LEN as u32 - 1) {
            return TestResult::Fail("TX ring size encode mismatch");
        }
        if ((v >> 16) & 0xFFFF) != (RING_LEN as u32 - 1) {
            return TestResult::Fail("RX ring size encode mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_ring_sizes_encoding);

    fn smoke_forcedeth_tx_stall_detection() -> TestResult {
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let mut posted = [0u64; RING_LEN];
        if tx_stalled(&posted, 1_000_000, timeout) {
            return TestResult::Fail("forcedeth idle TX ring reported stalled");
        }
        let now = 10_000_000u64;
        posted[5] = now;
        if tx_stalled(&posted, now + timeout, timeout) {
            return TestResult::Fail("forcedeth TX stall fired at exactly the timeout");
        }
        if !tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("forcedeth TX stall did not fire past the timeout");
        }
        // A second, later post does not mask the older stuck one...
        posted[6] = now + 100;
        if !tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("forcedeth later TX post masked the stuck descriptor");
        }
        // ...and completing the oldest clears the stall once nothing
        // aged remains.
        tx_note_completed(&mut posted, 5, now);
        if tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("forcedeth TX stall survived completing the stuck slot");
        }
        // A completion stamped for a different post leaves the
        // current post's stamp alone.
        tx_note_completed(&mut posted, 6, now);
        if posted[6] == 0 {
            return TestResult::Fail("forcedeth completion cleared a different post's stamp");
        }
        tx_note_completed(&mut posted, 6, now + 100);
        if tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("forcedeth empty TX ring reported stalled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/forcedeth", smoke_forcedeth_tx_stall_detection);

    /// Fake nForce MAC for the TX-timeout fixture: a 4 KiB MMIO
    /// backing page plus a sleep-pump that emulates the two
    /// hardware behaviours recovery depends on — `MacReset`
    /// self-clear and TX descriptor completion (VALID clear) once
    /// the test arms it. Built from the spec (register offsets,
    /// reset semantics), never from the implementation's constants.
    static FIXTURE_MMIO: AtomicU64 = AtomicU64::new(0);
    static FIXTURE_COMPLETE_TX: AtomicBool = AtomicBool::new(false);
    static FIXTURE_PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);

    fn fixture_pump() {
        let base = FIXTURE_MMIO.load(Ordering::Acquire);
        if base == 0 {
            return;
        }
        // SAFETY: fixture-owned fake MMIO; base is published by the
        // fixture and cleared on drop. The backing page is 4 KiB, so
        // every register offset below is in bounds.
        unsafe {
            let rst = core::ptr::read_volatile((base + REG_MAC_RESET) as *const u32);
            if rst & MAC_RESET_ASSERT != 0 {
                core::ptr::write_volatile(
                    (base + REG_MAC_RESET) as *mut u32,
                    rst & !MAC_RESET_ASSERT,
                );
            }
            if FIXTURE_COMPLETE_TX.load(Ordering::Acquire) {
                let ring_lo =
                    core::ptr::read_volatile((base + REG_TX_RING_PHYS) as *const u32) as u64;
                let ring_hi =
                    core::ptr::read_volatile((base + REG_TX_RING_PHYS_HIGH) as *const u32) as u64;
                let ring = (ring_hi << 32) | ring_lo;
                if ring != 0 {
                    for slot in 0..RING_LEN {
                        let flaglen = narf_memory::PhysAddr::new(ring + (slot * 8) as u64 + 4)
                            .kernel_mut_ptr::<u32>();
                        // SAFETY: fixture-owned DMA ring; slot bounded.
                        if core::ptr::read_volatile(flaglen) & TXD_VALID != 0 {
                            let v = core::ptr::read_volatile(flaglen);
                            core::ptr::write_volatile(flaglen, v & !TXD_VALID);
                        }
                    }
                }
            }
        }
    }

    struct TxTimeoutFixture {
        device: ForcedethNic,
        _mmio_mem: DmaBuffer,
    }

    impl TxTimeoutFixture {
        fn new() -> Self {
            // 4 KiB fake BAR0 (register window is 0x000..0x194).
            let mut mem = alloc_coherent(4096, DomainId::DRIVER_0).unwrap();
            mem.as_mut_slice().fill(0);
            let csr = MmioRegion {
                phys: mem.phys_addr(),
                virt: mem.as_mut_ptr() as u64,
                len: mem.len() as u64,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            // Seed the fake PHY's BMSR with link up (IEEE 802.3
            // Clause 22 bit 2): the watchdog gates on the link
            // sample. Note the seed is aspirational, not live: the
            // plain backing page cannot emulate the chip's
            // `MIIStatus` write-to-clear, so every `mii_rw` read
            // in the fixture fails with `MiiError` and
            // `live_link_up` falls back to the cached `link_up`
            // (seeded `true` below) — that fallback, not the
            // seeded BMSR value, is what the watchdog sees.
            // SAFETY: fixture-owned MMIO backing.
            unsafe {
                csr.write32(REG_MII_DATA, BMSR_LINK_UP as u32);
            }
            FIXTURE_MMIO.store(csr.virt, Ordering::Release);
            if !FIXTURE_PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
                narf_scheduler::sleep_pumps::register_nested_only(fixture_pump);
            }
            let tx_ring = alloc_coherent(RING_LEN * 8, DomainId::DRIVER_0).unwrap();
            let rx_ring = alloc_coherent(RING_LEN * 8, DomainId::DRIVER_0).unwrap();
            let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
            for _ in 0..RING_LEN {
                rx_pool.push(alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).unwrap());
            }
            let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
            for _ in 0..RING_LEN {
                tx_pool.push(alloc_coherent(2048, DomainId::DRIVER_0).unwrap());
            }
            let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
            let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
            let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            let device = ForcedethNic {
                mmio: csr,
                tx_ring,
                tx_pool,
                tx_head: IrqSafeSpinLock::new(0),
                tx_posted_at: IrqSafeSpinLock::new([0; RING_LEN]),
                tx_timeouts: AtomicU64::new(0),
                tx_resets: AtomicU64::new(0),
                recovering: AtomicBool::new(false),
                tx_epoch: AtomicU64::new(0),
                rx_ring,
                rx_pool,
                rx_head: IrqSafeSpinLock::new(0),
                mac,
                link_up: true,
                phy_addr: 0,
                txrxctl_bits: TXRXCTL_DESC_2,
                wol_enabled: AtomicBool::new(false),
                suspended: AtomicBool::new(false),
                addr: narf_bus::BusAddr::Mmio(mem.phys_addr()),
                ifname: crate::publish::IfName::new(),
                rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
                tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
            };
            // Bring-up register program (steps 7–10), minus the IRQ
            // install and the PHY scan: ring bases + sizes, RX
            // prime, mask, filter, path enable.
            let tx_phys = device.tx_ring.dma_addr().raw();
            let rx_phys = device.rx_ring.dma_addr().raw();
            // SAFETY: fixture-owned fake MMIO.
            unsafe {
                device.mmio.write32(REG_TX_RING_PHYS, tx_phys as u32);
                device.mmio.write32(REG_RX_RING_PHYS, rx_phys as u32);
                device
                    .mmio
                    .write32(REG_TX_RING_PHYS_HIGH, (tx_phys >> 32) as u32);
                device
                    .mmio
                    .write32(REG_RX_RING_PHYS_HIGH, (rx_phys >> 32) as u32);
                device.mmio.write32(
                    REG_RING_SIZES,
                    ((RING_LEN as u32 - 1) << RINGSZ_TXSHIFT)
                        | ((RING_LEN as u32 - 1) << RINGSZ_RXSHIFT),
                );
            }
            // Prime the RX descriptors from the pool (bring-up step 8).
            let rx_ring_phys = device.rx_ring.dma_addr().raw();
            for (i, slot) in device.rx_pool.iter().enumerate().take(RING_LEN) {
                let buf_phys = slot.dma_addr().raw();
                let d = Desc {
                    buf: buf_phys as u32,
                    flaglen: RXD_AVAIL | (RX_BUF_LEN as u32 & DESC_LEN_MASK_V2),
                };
                // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
                unsafe {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(rx_ring_phys + (i * 8) as u64)
                            .kernel_mut_ptr::<Desc>(),
                        d,
                    );
                }
            }
            // SAFETY: fixture-owned fake MMIO.
            unsafe {
                device.mmio.write32(REG_IRQ_MASK, 0);
                device.mmio.write32(REG_IRQ_STATUS, 0xFFFFFFFF);
                device
                    .mmio
                    .write32(REG_PACKET_FILTER, PFF_ALWAYS | PFF_MYADDR);
                device
                    .mmio
                    .write32(REG_RCV_CTL, RCV_CTL_RX_PATH_EN | RCV_CTL_START);
                device
                    .mmio
                    .write32(REG_XMIT_CTL, XMIT_CTL_TX_PATH_EN | XMIT_CTL_START);
            }
            core::mem::drop(rx_prod);
            core::mem::drop(tx_cons);
            Self {
                device,
                _mmio_mem: mem,
            }
        }
    }

    impl Drop for TxTimeoutFixture {
        fn drop(&mut self) {
            FIXTURE_COMPLETE_TX.store(false, Ordering::Release);
            FIXTURE_MMIO.store(0, Ordering::Release);
        }
    }

    fn smoke_forcedeth_tx_timeout_recovery_fixture() -> TestResult {
        let fixture = TxTimeoutFixture::new();
        let device = &fixture.device;
        // Link reads as up in the fixture: the plain MMIO backing
        // page cannot emulate `MIIStatus` write-to-clear, so the
        // live BMSR read fails and `live_link_up` falls back to
        // the cached `link_up` (seeded true in the fixture). Pin
        // that here so a fallback regression fails loudly instead
        // of surfacing as a watchdog that never fires.
        if !device.live_link_up() {
            return TestResult::Fail("forcedeth live link read as down in the fixture");
        }
        let frame = [0xAAu8; 64];
        // 1. Stall: the fake device never completes the descriptor,
        // so the synchronous post times out — the wedged ring, as
        // the field sees it.
        if device.transmit(&frame, &TxMeta::plain()).is_ok() {
            return TestResult::Fail("forcedeth TX completed against a wedged fake device");
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let posted = device.tx_posted_at.lock()[0];
        if posted == 0 {
            return TestResult::Fail("forcedeth TX post did not stamp a post time");
        }
        // 2. The watchdog does not fire inside the grace period...
        if device.check_tx_watchdog_at(posted + timeout) {
            return TestResult::Fail("forcedeth watchdog fired at exactly the timeout");
        }
        if device.tx_resets() != 0 || device.tx_timeouts() != 0 {
            return TestResult::Fail("forcedeth watchdog counted a recovery it did not fire");
        }
        // ...but fires past it, resets the controller, and the ring
        // comes back.
        if !device.check_tx_watchdog_at(posted + timeout + 1) {
            return TestResult::Fail("forcedeth watchdog did not fire past the timeout");
        }
        if device.tx_timeouts() != 1 || device.tx_resets() != 1 {
            return TestResult::Fail("forcedeth watchdog recovery was not counted");
        }
        // The recovery advanced the TX epoch exactly once, so a
        // `transmit` whose VALID poll straddled the reset cannot
        // mistake the zeroed ring for a completion.
        if device.tx_epoch.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("forcedeth recovery did not advance the TX epoch");
        }
        // SAFETY: fixture-owned fake MMIO.
        unsafe {
            let tx_lo = device.mmio.read32(REG_TX_RING_PHYS) as u64;
            let tx_hi = device.mmio.read32(REG_TX_RING_PHYS_HIGH) as u64;
            if (tx_hi << 32) | tx_lo != device.tx_ring.dma_addr().raw() {
                return TestResult::Fail("forcedeth recovery left a stale TX ring base");
            }
            if device.mmio.read32(REG_XMIT_CTL) & XMIT_CTL_TX_PATH_EN == 0 {
                return TestResult::Fail("forcedeth recovery left TX disabled");
            }
            if device.mmio.read32(REG_RCV_CTL) & RCV_CTL_RX_PATH_EN == 0 {
                return TestResult::Fail("forcedeth recovery left RX disabled");
            }
            if device.mmio.read32(REG_PACKET_FILTER) & PFF_MYADDR == 0 {
                return TestResult::Fail("forcedeth recovery left the packet filter unprogrammed");
            }
        }
        if tx_stalled(&device.tx_posted_at.lock(), posted + timeout + 1, timeout) {
            return TestResult::Fail("forcedeth TX stall survived the recovery");
        }
        // 3. Traffic resumes: with the fake device completing
        // descriptors again, a fresh post completes.
        FIXTURE_COMPLETE_TX.store(true, Ordering::Release);
        if device.transmit(&frame, &TxMeta::plain()).is_err() {
            return TestResult::Fail("forcedeth TX did not resume after recovery");
        }
        // The completed frame cleared its post time, so nothing
        // aged remains for the watchdog to fire on.
        if device.check_tx_watchdog_at(narf_time::now_cycles()) {
            return TestResult::Fail("forcedeth watchdog fired on an empty ring");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/forcedeth",
        smoke_forcedeth_tx_timeout_recovery_fixture
    );
}
