//! Realtek RTL8139 — clean-room.
//!
//! Spec: Realtek **"RTL8139D Series Programming Guide"** rev 1.4
//! (free PDF, realtek.com). The RTL8139 is the 10/100 Mbps PCI NIC
//! shipped in the late '90s / early 2000s; QEMU emulates it with
//! `-device rtl8139`. Stage cut: bring the chip out of reset,
//! read the MAC, install a 64 KiB RX ring + four 2 KiB TX buffers,
//! transmit a single Ethernet frame, drain RX into caller-supplied
//! storage.
//!
//! Register layout (BAR0, IO or MMIO — RTL8139 exposes both; we
//! use MMIO via BAR1):
//!
//! | offset | name      | width | description                   |
//! |--------|-----------|-------|-------------------------------|
//! | 0x00   | IDR0..5   | u8×6  | MAC address                   |
//! | 0x20   | TSAD0..3  | u32×4 | TX start address (DMA phys)   |
//! | 0x10   | TSD0..3   | u32×4 | TX status / size              |
//! | 0x30   | RBSTART   | u32   | RX buffer start (phys)        |
//! | 0x37   | CR        | u8    | Command Register              |
//! | 0x38   | CAPR      | u16   | Current Address of Packet Rd  |
//! | 0x3A   | CBR       | u16   | Current Buffer Address        |
//! | 0x3C   | IMR       | u16   | Interrupt Mask Register       |
//! | 0x3E   | ISR       | u16   | Interrupt Status Register     |
//! | 0x40   | TCR       | u32   | TX Configuration Register     |
//! | 0x44   | RCR       | u32   | RX Configuration Register     |
//! | 0x52   | CONFIG1   | u8    | Configuration Register 1      |

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────

pub const RTL8139_VENDOR: u16 = 0x10EC;
pub const RTL8139_DEVICE: u16 = 0x8139;

// ── Register offsets ────────────────────────────────────────────────

const REG_IDR0: u64 = 0x00;
const REG_TSD0: u64 = 0x10;
const REG_TSAD0: u64 = 0x20;
const REG_RBSTART: u64 = 0x30;
const REG_CR: u64 = 0x37;
const REG_CAPR: u64 = 0x38;
const REG_IMR: u64 = 0x3C;
const REG_ISR: u64 = 0x3E;
const REG_TCR: u64 = 0x40;
const REG_RCR: u64 = 0x44;
const REG_CONFIG1: u64 = 0x52;

// CR bits.
const CR_BUFE: u8 = 1 << 0; // Buffer Empty (RX)
const CR_TE: u8 = 1 << 2; // TX Enable
const CR_RE: u8 = 1 << 3; // RX Enable
const CR_RST: u8 = 1 << 4; // Software reset (self-clearing)

// RCR bits.
const RCR_AAP: u32 = 1 << 0; // Accept All Packets
const RCR_APM: u32 = 1 << 1; // Accept Physical Match
const RCR_AM: u32 = 1 << 2; // Accept Multicast
const RCR_AB: u32 = 1 << 3; // Accept Broadcast
const RCR_WRAP: u32 = 1 << 7; // Wrap RX buffer
const RCR_RBLEN_8K: u32 = 0; // bits[12:11] = 0 → 8 KB + 16 byte WRAP
const RCR_RBLEN_64K: u32 = 0b11 << 11; // bits[12:11] = 3 → 64 KB + 16

// TX descriptor / status bits (TSD).
const TSD_OWN: u32 = 1 << 13; // OWN — set by chip when done
const TSD_TOK: u32 = 1 << 15; // Transmit OK

// RX header (first 4 bytes of each packet in RX ring).
const RX_OK: u16 = 1 << 0;

// 64 KB + 16 byte slack for `RCR_RBLEN_64K`. Spec §3.4.4 mandates
// the 16 byte tail — chip writes a partial header past the
// 65536-byte limit when a packet wraps.
const RX_RING_BYTES: usize = 65536 + 16 + 1500;
// 4 TX buffers × 2 KiB max packet.
const TX_BUF_COUNT: usize = 4;
const TX_BUF_BYTES: usize = 2048;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Rtl8139Error {
    BarMapFailed,
    ResetTimeout,
    QueueTooSmall,
    /// All four TX buffers are owned by the chip.
    TxBusy,
}

pub struct Rtl8139 {
    mmio: MmioRegion,
    mac: [u8; 6],
    rx_ring: DmaBuffer,
    tx_bufs: [DmaBuffer; TX_BUF_COUNT],
    /// Read offset into the cyclic RX ring.
    rx_offset: IrqSafeSpinLock<usize>,
    /// Round-robin index for the next TX descriptor.
    tx_index: IrqSafeSpinLock<usize>,
    pub ready: bool,
}

impl core::fmt::Debug for Rtl8139 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8139")
            .field("mac", &self.mac)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl Rtl8139 {
    /// Bring up the controller.
    ///
    /// # Safety
    /// Caller owns BAR1 (MMIO) exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Rtl8139Error> {
        // SAFETY: caller-asserted. RTL8139 advertises both BAR0
        // (IO) and BAR1 (MMIO); MMIO is more portable + cross-arch
        // friendly.
        let mmio = unsafe { map_bar(device, 1) }.map_err(|_| Rtl8139Error::BarMapFailed)?;

        // 1. Power on + take out of low-power mode (CONFIG1 = 0).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write8(REG_CONFIG1, 0);
        }

        // 2. Software reset — write CR.RST, poll until self-clears.
        // SAFETY: same.
        unsafe {
            mmio.write8(REG_CR, CR_RST);
        }
        // SAFETY: identity-mapped MMIO. responsive_spin ticks
        // sleep_pumps so FB cursor / serial drain stay alive.
        narf_scheduler::responsive_spin(
            || unsafe { mmio.read8(REG_CR) } & CR_RST == 0,
            1_000_000,
        );
        // SAFETY: same.
        let post = unsafe { mmio.read8(REG_CR) };
        if post & CR_RST != 0 {
            return Err(Rtl8139Error::ResetTimeout);
        }

        // 3. Read MAC from IDR0..5.
        let mut mac = [0u8; 6];
        // SAFETY: same.
        for i in 0..6 {
            mac[i] = unsafe { mmio.read8(REG_IDR0 + i as u64) };
        }

        // 4. Allocate RX + TX buffers (alloc_coherent zero-fills).
        let rx_ring = alloc_coherent(RX_RING_BYTES, DomainId::DRIVER_0)
            .map_err(|_| Rtl8139Error::BarMapFailed)?;
        let tx_bufs: [DmaBuffer; TX_BUF_COUNT] = [
            alloc_coherent(TX_BUF_BYTES, DomainId::DRIVER_0)
                .map_err(|_| Rtl8139Error::BarMapFailed)?,
            alloc_coherent(TX_BUF_BYTES, DomainId::DRIVER_0)
                .map_err(|_| Rtl8139Error::BarMapFailed)?,
            alloc_coherent(TX_BUF_BYTES, DomainId::DRIVER_0)
                .map_err(|_| Rtl8139Error::BarMapFailed)?,
            alloc_coherent(TX_BUF_BYTES, DomainId::DRIVER_0)
                .map_err(|_| Rtl8139Error::BarMapFailed)?,
        ];

        // 5. Program RX buffer + TX descriptor base addresses.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(
                REG_RBSTART,
                (rx_ring.phys_addr().raw() & 0xFFFF_FFFF) as u32,
            );
            for i in 0..TX_BUF_COUNT {
                mmio.write32(
                    REG_TSAD0 + (i as u64) * 4,
                    (tx_bufs[i].phys_addr().raw() & 0xFFFF_FFFF) as u32,
                );
            }
        }

        // 6. RX configuration: accept broadcast + physical match +
        //    multicast + all-packets (promisc), wrap, 64 KB ring.
        // SAFETY: same.
        unsafe {
            mmio.write32(
                REG_RCR,
                RCR_AAP | RCR_APM | RCR_AM | RCR_AB | RCR_WRAP | RCR_RBLEN_64K,
            );
            // TX configuration: leave at default (chip auto-tunes).
            mmio.write32(REG_TCR, 0);
        }

        // 7. Mask all IRQs (we poll); clear status by writing back.
        // SAFETY: same.
        unsafe {
            mmio.write16(REG_IMR, 0);
            let isr = mmio.read16(REG_ISR);
            mmio.write16(REG_ISR, isr);
        }

        // 8. Enable RX + TX.
        // SAFETY: same.
        unsafe {
            mmio.write8(REG_CR, CR_TE | CR_RE);
        }

        Ok(Self {
            mmio,
            mac,
            rx_ring,
            tx_bufs,
            rx_offset: IrqSafeSpinLock::new(0),
            tx_index: IrqSafeSpinLock::new(0),
            ready: true,
        })
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Transmit a single Ethernet frame on a free TX buffer. Polls
    /// the OWN bit. Frame length must be ≤ `TX_BUF_BYTES` and ≥ 60
    /// (the chip auto-pads runts to 60, but rejects < 60 in some
    /// modes).
    pub fn tx(&self, frame: &[u8]) -> Result<(), Rtl8139Error> {
        if frame.is_empty() || frame.len() > TX_BUF_BYTES {
            return Err(Rtl8139Error::QueueTooSmall);
        }
        let mut idx_lock = self.tx_index.lock();
        let idx = *idx_lock;
        // Wait for this slot to be free (OWN cleared by chip after
        // the previous transmission). responsive_spin ticks
        // sleep_pumps. After power-on TSD reads 0, which counts as
        // OWN=0 + never-transmitted; in steady state we see
        // OWN-clear after the prior TX completes.
        let free = narf_scheduler::responsive_spin(
            || {
                // SAFETY: identity-mapped MMIO.
                let tsd = unsafe { self.mmio.read32(REG_TSD0 + (idx as u64) * 4) };
                tsd & TSD_OWN == 0 || (tsd & TSD_TOK) != 0
            },
            10_000_000,
        );
        if !free {
            return Err(Rtl8139Error::TxBusy);
        }
        let buf_phys = self.tx_bufs[idx].phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((buf_phys + i as u64) as *mut u8, *b);
            }
        }
        // Pad runts to 60 bytes — the chip adds the 4-byte FCS.
        let len = frame.len().max(60);
        // TSD: bits[12:0] = packet size. Writing this clears OWN
        // (chip claim).
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TSD0 + (idx as u64) * 4, len as u32);
        }
        *idx_lock = (idx + 1) % TX_BUF_COUNT;
        Ok(())
    }

    /// Drain one frame from the RX ring into `out`. Returns the
    /// number of bytes copied (excluding the 4-byte RX header +
    /// the trailing 4-byte FCS the chip strips for us when
    /// configured), or 0 if the ring is empty.
    pub fn rx(&self, out: &mut [u8]) -> usize {
        // SAFETY: identity-mapped MMIO.
        let cr = unsafe { self.mmio.read8(REG_CR) };
        if cr & CR_BUFE != 0 {
            return 0;
        }

        let mut off_lock = self.rx_offset.lock();
        let off = *off_lock;
        let ring_phys = self.rx_ring.phys_addr().raw();
        // Each packet starts with a 4-byte header:
        //   +0 u16 status | +2 u16 length (incl. CRC)
        // SAFETY: identity-mapped DMA.
        let status = unsafe { core::ptr::read_volatile((ring_phys + off as u64) as *const u16) };
        // SAFETY: same.
        let len = unsafe { core::ptr::read_volatile((ring_phys + (off + 2) as u64) as *const u16) };
        if status & RX_OK == 0 || len < 4 || len as usize > 1518 + 4 {
            // Poisoned / corrupt — reset the ring.
            // SAFETY: identity-mapped MMIO.
            unsafe {
                self.mmio.write8(REG_CR, CR_TE);
            }
            // SAFETY: same.
            unsafe {
                self.mmio.write8(REG_CR, CR_TE | CR_RE);
            }
            *off_lock = 0;
            return 0;
        }
        // Copy frame (excluding the 4-byte trailing CRC).
        let frame_len = (len as usize).saturating_sub(4);
        let copy = frame_len.min(out.len());
        // SAFETY: identity-mapped DMA.
        for i in 0..copy {
            out[i] = unsafe {
                core::ptr::read_volatile((ring_phys + (off + 4 + i) as u64) as *const u8)
            };
        }
        // Advance: header (4) + payload (len) rounded up to 4 bytes.
        let advance = ((4 + len as usize) + 3) & !3;
        let new_off = (off + advance) % 65536;
        *off_lock = new_off;
        // CAPR is read by chip - 0x10 (per RTL programming guide).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write16(REG_CAPR, (new_off as u16).wrapping_sub(0x10));
        }
        copy
    }

    pub fn link_up(&self) -> bool {
        // MSR (Media Status Register) at 0x58, bit 2 = LINK_DOWN
        // (0 = link up, 1 = link down).
        // SAFETY: identity-mapped MMIO.
        let msr = unsafe { self.mmio.read8(0x58) };
        msr & (1 << 2) == 0
    }
}

// ── HwNic adapter ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct Rtl8139Nic;

impl crate::HwNic for Rtl8139Nic {
    fn name(&self) -> &'static str {
        "rtl8139"
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
        crate::NicModel::RealtekRtl8139
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        TX_BUF_COUNT
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Rtl8139>> = IrqSafeSpinLock::new(None);

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
    let dev = match unsafe { Rtl8139::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("rtl8139"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(RTL8139_VENDOR),
        pci_did: Some(RTL8139_DEVICE),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "rtl8139",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: RTL8139_VENDOR,
            device: RTL8139_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Rtl8139) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
