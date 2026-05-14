//! e1000 / e1000e family driver — Intel 8254x and 8257x Gigabit
//! Ethernet controllers.
//!
//! Spec: Intel "PCI/PCI-X Family of Gigabit Ethernet Controllers
//! Software Developer's Manual" (8254x) §13 (Register Descriptions)
//! and §3.2 (Receive Functionality), plus the "Intel 82574L Gigabit
//! Ethernet Controller Datasheet" (8257x). The two families share
//! enough register layout that one driver covers both with a small
//! probe-time discriminator.
//!   <https://www.intel.com/content/www/us/en/sdm.html>
//!   <https://www.intel.com/content/dam/doc/manual/8254x-software-developers-manual.pdf>
//!   <https://www.intel.com/content/dam/doc/datasheet/82574l-gbe-controller-datasheet.pdf>
//!
//! Bring-up sequence: reset the device, read the MAC address from
//! RAL/RAH, allocate TX + RX descriptor rings, set link up, then
//! attach an IRQ delivery path:
//!
//!   1. Try MSI-X (PCIe 8257x parts expose it via the standard cap
//!      list — see 82574L datasheet §1.4.4 and §6).
//!   2. Fall back to legacy INTx routed through the AML `_PRT`
//!      table → IOAPIC redirection-table entry. PCI INTx is level-
//!      triggered, active-low (PCI Local Bus Spec §2.2.6); the ISR
//!      reads ICR (Interrupt Cause Read; auto-clears on read per
//!      §13.4.17) so the device deasserts the line.
//!   3. Fall back to polled completion if neither IRQ path is
//!      reachable. Polled `tx`/`rx_recv` are kept regardless so
//!      bring-up tests work in the no-IRQ environment.
//!
//! IMS (Interrupt Mask Set, §13.4.20) is programmed with the
//! standard "frame arrived / TX completed / receiver overrun" set:
//! RXT0 (RX timer expired) + TXDW (TX desc written back) + RXO
//! (receiver overrun). RXDMT0 (RX desc min threshold) is included
//! so we can refill before the ring underflows.
//!
//! Register subset (all 4-byte aligned, BAR0 + offset):
//!
//! | offset  | name | description                       |
//! |---------|------|-----------------------------------|
//! | 0x0000  | CTRL | Device Control                    |
//! | 0x0008  | STATUS| Device Status                    |
//! | 0x0014  | EERD | EEPROM Read                       |
//! | 0x00C0  | ICR  | Interrupt Cause Read (auto-clear) |
//! | 0x00D0  | IMS  | Interrupt Mask Set/Read           |
//! | 0x00D8  | IMC  | Interrupt Mask Clear              |
//! | 0x0100  | RCTL | Receive Control                   |
//! | 0x0400  | TCTL | Transmit Control                  |
//! | 0x2800  | RDBAL| RX Descriptor Base Low            |
//! | 0x2804  | RDBAH| RX Descriptor Base High           |
//! | 0x2808  | RDLEN| RX Descriptor Ring Length         |
//! | 0x2810  | RDH  | RX Descriptor Head                |
//! | 0x2818  | RDT  | RX Descriptor Tail                |
//! | 0x3800  | TDBAL| TX Descriptor Base Low            |
//! | 0x3804  | TDBAH| TX Descriptor Base High           |
//! | 0x3808  | TDLEN| TX Descriptor Ring Length         |
//! | 0x3810  | TDH  | TX Descriptor Head                |
//! | 0x3818  | TDT  | TX Descriptor Tail                |
//! | 0x5400  | RAL  | Receive Address Low (MAC[0..4])   |
//! | 0x5404  | RAH  | Receive Address High (MAC[4..6] + valid bit) |

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs we recognise ─────────────────────────────────────

/// Vendor: Intel.
pub const E1000_VENDOR: u16 = 0x8086;

/// Classic 82540EM (`-device e1000`).
pub const E1000_DEV_82540EM: u16 = 0x100E;
/// 82545EM Gigabit.
pub const E1000_DEV_82545EM: u16 = 0x100F;
/// QEMU's `-device e1000-82544gc`.
pub const E1000_DEV_82544GC: u16 = 0x100C;
/// 82574L (used by QEMU q35 default + `-device e1000e`).
pub const E1000E_DEV_82574L: u16 = 0x10D3;
/// I217-LM, found on real Lenovo laptops.
pub const E1000E_DEV_I217LM: u16 = 0x153A;

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
const REG_EERD: u64 = 0x0014;
/// Interrupt Cause Read — reading this register returns the set of
/// pending causes and clears them all (8254x SDM §13.4.17). The ISR
/// reads ICR exactly once per IRQ to acknowledge the device and
/// deassert legacy INTx.
const REG_ICR: u64 = 0x00C0;
const REG_IMS: u64 = 0x00D0;
/// Interrupt Mask Clear — writing 1 to a bit disables that cause's
/// IRQ delivery (8254x SDM §13.4.22).
const REG_IMC: u64 = 0x00D8;
const REG_RCTL: u64 = 0x0100;
const REG_TCTL: u64 = 0x0400;
const REG_RDBAL: u64 = 0x2800;
const REG_RDBAH: u64 = 0x2804;
const REG_RDLEN: u64 = 0x2808;
const REG_RDH: u64 = 0x2810;
const REG_RDT: u64 = 0x2818;
const REG_TDBAL: u64 = 0x3800;
const REG_TDBAH: u64 = 0x3804;
const REG_TDLEN: u64 = 0x3808;
const REG_TDH: u64 = 0x3810;
const REG_TDT: u64 = 0x3818;
const REG_RAL0: u64 = 0x5400;
const REG_RAH0: u64 = 0x5404;

// CTRL bits.
const CTRL_RST: u32 = 1 << 26;
const CTRL_SLU: u32 = 1 << 6; // Set Link Up

// TCTL bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3; // Pad Short Packets

// TX descriptor flags.
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1; // Insert FCS
const TXD_CMD_RS: u8 = 1 << 3; // Report Status
const TXD_STAT_DD: u8 = 1 << 0; // Done

// RCTL bits (Receive Control register).
const RCTL_EN: u32 = 1 << 1; // Receiver Enable
const RCTL_UPE: u32 = 1 << 3; // Unicast Promiscuous
const RCTL_MPE: u32 = 1 << 4; // Multicast Promiscuous
const RCTL_BAM: u32 = 1 << 15; // Broadcast Accept
const RCTL_BSIZE_2K: u32 = 0 << 16; // Buffer Size = 2048
const RCTL_SECRC: u32 = 1 << 26; // Strip Ethernet CRC

// RX descriptor status flags.
const RXD_STAT_DD: u8 = 1 << 0; // Done
const RXD_STAT_EOP: u8 = 1 << 1; // End of Packet

// IMS / ICR bit layout (8254x SDM §13.4.17 + §13.4.20). Same set
// applies to ICR (read-to-clear) and IMS (write-1-to-set). The
// 82574L datasheet §10.2 keeps the same bit positions; e1000e
// adds extra bits we don't enable.
/// TXDW — Transmit Descriptor Written Back. Fires when a TX
/// descriptor with RS set has been written back with DD = 1.
pub const IMS_TXDW: u32 = 1 << 0;
/// TXQE — Transmit Queue Empty. Fires once the TX ring drains.
pub const IMS_TXQE: u32 = 1 << 1;
/// LSC — Link Status Change.
pub const IMS_LSC: u32 = 1 << 2;
/// RXSEQ — Receive Sequence Error.
pub const IMS_RXSEQ: u32 = 1 << 3;
/// RXDMT0 — Receive Descriptor Minimum Threshold (head reached the
/// "low watermark" — driver should refill).
pub const IMS_RXDMT0: u32 = 1 << 4;
/// RXO — Receiver FIFO Overrun.
pub const IMS_RXO: u32 = 1 << 6;
/// RXT0 — Receiver Timer Expired (a frame landed in the ring and
/// the receive interrupt timer expired). Standard "RX done"
/// indicator under per-frame interrupts (RDTR = 0).
pub const IMS_RXT0: u32 = 1 << 7;

/// Default IMS bring-up mask: RX completion + TX completion + RX
/// overrun + low-threshold. RXSEQ is included so we can observe
/// link-side framing errors.
const IMS_DEFAULT: u32 =
    IMS_RXT0 | IMS_RXDMT0 | IMS_RXO | IMS_RXSEQ | IMS_TXDW | IMS_TXQE | IMS_LSC;

const TX_RING_LEN: usize = 8;
const RX_RING_LEN: usize = 8;
/// Buffer size for each RX entry — must match RCTL.BSIZE.
const RX_BUF_LEN: usize = 2048;

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
struct RxDesc {
    addr: u64,
    length: u16,
    csum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);

/// e1000 driver errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum E1000Error {
    BarMapFailed,
    NoMemory,
    UnsupportedDevice,
    /// Caller passed a frame larger than 1518 bytes.
    FrameTooLong,
    /// TX descriptor never completed.
    TxTimeout,
}

/// Live e1000 controller. Holds the MMIO mapping + the TX descriptor
/// ring's DMA buffer. Each frame transmits through a per-call DMA
/// scratch buffer that drops after completion.
pub struct E1000 {
    mmio: MmioRegion,
    /// TX descriptor-ring DMA buffer.
    tx_ring: DmaBuffer,
    /// Persistent TX frame buffers, one per descriptor slot
    /// (audit #4: pre-fix `tx()` did `alloc_coherent(4096)` per
    /// frame and dropped it on return — under AMD-Vi a freed
    /// page could be reused while the NIC still had a delayed
    /// DMA in flight, corrupting whatever owns the recycled
    /// page). Pool sized to TX_RING_LEN; slot index matches the
    /// descriptor index, so `tx()` writes into `tx_pool[slot]`
    /// before pointing the descriptor's `addr` at it.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side TDT cursor (tail).
    tx_tail: IrqSafeSpinLock<u32>,
    /// RX descriptor-ring DMA buffer.
    rx_ring: DmaBuffer,
    /// RX buffer pool — one DMA page per descriptor (`RX_BUF_LEN`
    /// bytes consumed; remainder unused).
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX head cursor (next descriptor to inspect for
    /// completion). The hardware writes to RDT and we lag behind
    /// reading at this index.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from RAL/RAH at bring-up.
    pub mac: [u8; 6],
    /// True after CTRL_SLU has been set + STATUS reports link up.
    pub link_up: bool,
    /// MSI-X table mapping when MSI-X is enabled. Holds the table
    /// alive for the device lifetime; dropping it would unmap the
    /// MSI-X BAR.
    _msix: Option<MsixTable>,
    /// IDT vector bound to the device's IRQ (MSI-X table entry 0
    /// or the IOAPIC GSI route). `None` means we fell back to
    /// polled-only completion.
    pub irq_vector: Option<u8>,
}

impl core::fmt::Debug for E1000 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("E1000")
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

/// MMIO base of the IRQ-attached e1000, shared with the static ISR
/// so it can read ICR (auto-clear, §13.4.17) and deassert legacy
/// INTx. 0 = no controller bound (handler short-circuits).
///
/// Single-controller invariant matches the rest of the driver:
/// `CONTROLLER` is a single `Option<E1000>` slot below.
static ISR_MMIO_BASE: AtomicU64 = AtomicU64::new(0);

/// Sync ISR: read ICR to acknowledge + deassert level-triggered INTx,
/// then return. The dispatch layer (`narf_interrupts::dispatch::on_irq`)
/// bumps the per-vector fire-count and wakes the registered waker; the
/// `rx_async`/`tx_async` consumers then run the actual descriptor
/// drain on a normal task.
fn e1000_isr() {
    let base = ISR_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: `base` is the device's BAR0 phys, identity-mapped at
    // bring-up; ICR (offset 0xC0) is well inside the e1000 register
    // window. The read auto-clears all pending cause bits per 8254x
    // SDM §13.4.17 — this is the documented acknowledge for
    // level-triggered INTx delivery and a no-op for MSI-X (which
    // is edge-triggered but tolerates the read).
    unsafe {
        let _icr = narf_arch::mmio::read32(base + REG_ICR);
    }
}

impl E1000 {
    /// Bring up the controller: reset, read MAC, install RX + TX
    /// rings, set link up, attach IRQ delivery (MSI-X → INTx →
    /// polled fallback) and program IMS for the standard RX/TX
    /// completion mask.
    ///
    /// # Safety
    /// Caller owns the device's BAR exclusively for the duration of
    /// init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, E1000Error> {
        // SAFETY: caller owns the device.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| E1000Error::BarMapFailed)?;

        // 1. Reset (CTRL.RST = 1; cleared by hardware after reset).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_CTRL, CTRL_RST);
        }
        // Wait for RST to clear. responsive_spin_until ticks
        // sleep_pumps every ~4096 iters so FB cursor / serial drain
        // stay alive. e1000 datasheet §13.3.1: CTRL.RST self-clears
        // within ~10 ms; 100 ms is the wedge threshold.
        narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST == 0,
            narf_time::Deadline::after_ms(100),
        );

        // 2. Read MAC from RAL/RAH.
        // SAFETY: identity-mapped.
        let ral = unsafe { mmio.read32(REG_RAL0) };
        let rah = unsafe { mmio.read32(REG_RAH0) };
        let mac = [
            (ral & 0xFF) as u8,
            ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8) & 0xFF) as u8,
        ];

        // 3. Mask all interrupt causes during bring-up. IMC is
        //    write-1-to-clear (8254x SDM §13.4.22); writing all-ones
        //    leaves IMS = 0 and prevents stale IRQs while we program
        //    the rings. We re-enable the per-cause mask in IMS at the
        //    end of bring-up once the ISR is installed.
        // SAFETY: identity-mapped.
        unsafe {
            mmio.write32(REG_IMC, !0u32);
            // Clear any pending causes by reading ICR (read-to-clear).
            let _ = mmio.read32(REG_ICR);
        }

        // 4. Allocate TX descriptor ring + persistent per-slot
        //    frame buffers. The buffers outlive any single tx()
        //    call so a delayed DMA write (AMD-Vi turn-around
        //    latency) can't land on a freed page.
        let tx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
        let ring_phys = tx_ring.phys_addr().raw();
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(TX_RING_LEN);
        for _ in 0..TX_RING_LEN {
            let b =
                alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
            tx_pool.push(b);
        }
        // Zero the ring (alloc_coherent guarantees fresh memory but
        // we're explicit).
        // SAFETY: identity-mapped DMA.
        unsafe {
            for i in 0..(TX_RING_LEN * 16) {
                core::ptr::write_volatile((ring_phys + i as u64) as *mut u8, 0);
            }
        }
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_TDBAL, ring_phys as u32);
            mmio.write32(REG_TDBAH, (ring_phys >> 32) as u32);
            mmio.write32(REG_TDLEN, (TX_RING_LEN * 16) as u32);
            mmio.write32(REG_TDH, 0);
            mmio.write32(REG_TDT, 0);
        }
        // 5. Enable TX. PSP = pad short packets to 64 bytes (Ethernet
        //    minimum frame size). Collision threshold + collision
        //    distance are spec-default — bits 12..21 stay zero in our
        //    minimal config.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
        }

        // 5b. Allocate RX descriptor ring + buffer pool.
        let rx_ring = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
        let rx_ring_phys = rx_ring.phys_addr().raw();
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for i in 0..RX_RING_LEN {
            let buf = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| E1000Error::NoMemory)?;
            let buf_phys = buf.phys_addr().raw();
            let desc = RxDesc {
                addr: buf_phys,
                length: 0,
                csum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            // SAFETY: identity-mapped DMA ring.
            unsafe {
                core::ptr::write_volatile((rx_ring_phys + (i * 16) as u64) as *mut RxDesc, desc);
            }
            rx_pool.push(buf);
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDBAL, rx_ring_phys as u32);
            mmio.write32(REG_RDBAH, (rx_ring_phys >> 32) as u32);
            mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(REG_RDH, 0);
            // RDT points to the last *available* slot (i.e. one past
            // the last filled slot). With all slots filled, RDT =
            // RX_RING_LEN - 1.
            mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);
            // RCTL: enable, accept broadcast/unicast/multicast,
            // strip CRC, 2K buffers.
            mmio.write32(
                REG_RCTL,
                RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_MPE | RCTL_SECRC | RCTL_BSIZE_2K,
            );
        }

        // 6. Set link up.
        // SAFETY: same.
        let cur = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, cur | CTRL_SLU);
        }
        // STATUS bit 1 = LU (link up). QEMU e1000 reports up
        // immediately on user-mode net.
        // SAFETY: same.
        let status = unsafe { mmio.read32(REG_STATUS) };
        let link_up = status & (1 << 1) != 0;

        // 7. Try to attach an IRQ delivery path. Mirror the
        //    `xhci.rs` MSI-X → INTx → polled fallback chain.
        let (msix, irq_vector, used_intx) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v), false),
            Err(_) => match Self::try_install_intx(cap, device) {
                Some(v) => (None, Some(v), true),
                None => (None, None, false),
            },
        };

        // Publish MMIO base for the static ISR before installing the
        // handler — otherwise an early INTx could race and find a
        // zero base.
        if irq_vector.is_some() {
            ISR_MMIO_BASE.store(mmio.phys.raw(), Ordering::Release);
        }
        if let Some(v) = irq_vector {
            narf_interrupts::install_handler(v, e1000_isr);
        }

        // 8. Adjust the PCI Command register based on which IRQ path
        //    won. INTx delivery requires the legacy interrupt enable
        //    (i.e. INTX_DISABLE *cleared*); MSI-X delivery is happy
        //    with INTX_DISABLE set so the device can't double-fire.
        //
        //    The probe path enables MEM_SPACE + BUS_MASTER but leaves
        //    INTx behaviour to the driver. We only program the bit
        //    we need to flip here.
        if !used_intx && irq_vector.is_some() {
            // MSI-X path: explicitly mask legacy INTx.
            let _ = narf_bus::pci::set_command(cap, device, narf_bus::pci::cmd::INTX_DISABLE);
        }

        // 9. Enable interrupt causes. ICR was cleared above; IMS is
        //    a write-1-to-set register (8254x SDM §13.4.20).
        //    Skip if no IRQ vector is bound — keep the "all masked"
        //    state from step 3 so polled callers don't see spurious
        //    cause bits.
        if irq_vector.is_some() {
            // SAFETY: identity-mapped MMIO.
            unsafe {
                mmio.write32(REG_IMS, IMS_DEFAULT);
            }
        }

        Ok(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_tail: IrqSafeSpinLock::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            _msix: msix,
            irq_vector,
        })
    }

    /// Walk the controller's MSI-X capability, allocate an IDT
    /// vector + table slot, program slot 0 to deliver to BSP, and
    /// flip the global MSI-X enable. Returns `(table, vector)` on
    /// success. Failure propagates to `try_install_intx`.
    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(MsixTable, u8), E1000Error> {
        let mut msix = enable_msix(cap, device).map_err(|_| E1000Error::NoMemory)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| E1000Error::NoMemory)?;
        let _ = msix.alloc_vector().ok_or(E1000Error::NoMemory)?;
        // Deliver to APIC id 0 (BSP). On aarch64 this routes through
        // the GIC ITS doorbell with EventID=v.
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X
        // table (no other writer); we issue this write before the
        // global enable so the device can't fire stale data.
        let _ = unsafe { msix.program_vector(0, 0, v) }.map_err(|_| E1000Error::NoMemory)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        let _ = unsafe { msix.enable() }.map_err(|_| E1000Error::NoMemory)?;
        Ok((msix, v))
    }

    /// Legacy INTx fallback: read PCI INTERRUPT_PIN, look up the
    /// (bridge, slot, pin) triple in the AML `_PRT` routing table,
    /// allocate an IDT vector, and program the IOAPIC redirection-
    /// table entry for the resolved GSI.
    ///
    /// PCI INTx is level-triggered, active-low (PCI Local Bus Spec
    /// §2.2.6). Returns the allocated vector, or `None` on any
    /// failure (caller falls through to polled completion).
    #[cfg(target_arch = "x86_64")]
    fn try_install_intx(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Option<u8> {
        let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
        if pin == 0 || pin > 4 {
            return None;
        }
        let slot = match device.kind {
            narf_bus::BusKind::Pcie { addr, .. } => addr.device,
            _ => return None,
        };
        // PCI _PRT pin is 0-based (0=INTA..3=INTD); cfg-space pin is
        // 1-based. Map between them.
        let prt_pin = pin - 1;
        // Today every QEMU q35 bridge AML lives at "\\_SB.PCI0";
        // real consumer BIOSes match this convention.
        let route = narf_aml::irq_routing::route_for("\\_SB.PCI0", slot, prt_pin)?;
        if route.entry.source.is_some() {
            // Named-link _PRT entry — needs link-device _CRS
            // evaluation to learn the current GSI.
            return None;
        }
        let gsi = route.entry.source_index;
        let v = narf_interrupts::vector::alloc().ok()?;
        // Program IOAPIC: PCI INTx is level / active-low. The
        // handler is installed after this returns by the bring-up
        // path so the dispatch table sees the e1000 ISR before the
        // first IRQ can be delivered (vector::alloc reserves the
        // slot but doesn't open it for delivery).
        // SAFETY: vector reserved above; route_gsi_to_vector only
        // programs the IOAPIC redirection-table entry.
        let ok = unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(
                gsi,
                v,
                0,
                narf_acpi::ioapic::POLARITY_LOW | narf_acpi::ioapic::TRIGGER_LEVEL,
            )
        };
        if !ok {
            return None;
        }
        Some(v)
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn try_install_intx(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
        None
    }

    /// Transmit a single Ethernet frame. Polled completion via the
    /// TX descriptor's DD (Descriptor Done) status bit. Available
    /// regardless of whether IRQ delivery is wired — the polled
    /// path is what bring-up tests run, and it's also the synchronous
    /// fallback for callers that can't await.
    pub fn tx(&self, frame: &[u8]) -> Result<(), E1000Error> {
        if frame.len() == 0 || frame.len() > 1518 {
            return Err(E1000Error::FrameTooLong);
        }
        // Pick the next TX descriptor slot, then reuse that
        // slot's persistent DMA buffer (audit #4 — pre-fix this
        // alloc_coherent'd a fresh page per frame and dropped it
        // on return).
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked by
        // the FrameTooLong guard above (1518 < 4096).
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = TxDesc {
            addr: phys,
            length: frame.len() as u16,
            cso: 0,
            cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
            status: 0,
            css: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut TxDesc, desc);
        }
        // Bump TDT.
        let next_tail = (*tail_g + 1) % (TX_RING_LEN as u32);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TDT, next_tail);
        }
        *tail_g = next_tail;
        drop(tail_g);

        // Poll for DD. responsive_spin_until ticks sleep_pumps.
        // 250 ms wall-clock budget covers worst-case Tx-side
        // congestion stall.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) } & TXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(E1000Error::TxTimeout);
        }
        Ok(())
    }

    /// Inspect the TX descriptor most recently posted at `slot` and
    /// return whether its DD bit is set. Used by `tx_async` to
    /// detect completion after `wait_for_irq` returns.
    fn tx_slot_done(&self, slot: usize) -> bool {
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        // SAFETY: identity-mapped DMA ring; slot < TX_RING_LEN.
        let status = unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) };
        status & TXD_STAT_DD != 0
    }

    /// Enqueue a frame and return the TX descriptor slot index. The
    /// caller is responsible for awaiting completion (via the
    /// `tx_async` wrapper, which holds the scratch buffer alive
    /// until DD is observed).
    fn tx_enqueue(&self, frame: &[u8]) -> Result<usize, E1000Error> {
        if frame.len() == 0 || frame.len() > 1518 {
            return Err(E1000Error::FrameTooLong);
        }
        // Persistent per-slot buffer (audit #4); same change as the
        // sync `tx()` path. Returns just the slot id now since the
        // buffer is owned by the controller and doesn't need to
        // be moved through the async future.
        let mut tail_g = self.tx_tail.lock();
        let slot = (*tail_g) as usize % TX_RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;
        let desc = TxDesc {
            addr: phys,
            length: frame.len() as u16,
            cso: 0,
            cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
            status: 0,
            css: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring page.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut TxDesc, desc);
        }
        let next_tail = (*tail_g + 1) % (TX_RING_LEN as u32);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TDT, next_tail);
        }
        *tail_g = next_tail;
        Ok(slot)
    }

    /// Drain one received frame from the RX ring, copying it into
    /// `out` and returning the number of bytes. Returns 0 if no
    /// frame is currently pending. After consuming, the descriptor
    /// is rearmed and RDT is bumped so the device sees the freshly-
    /// available slot.
    pub fn rx_recv(&self, out: &mut [u8]) -> usize {
        let mut head_g = self.rx_head.lock();
        let head = (*head_g) as usize;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring; head < RX_RING_LEN.
        let desc = unsafe { core::ptr::read_volatile(desc_addr as *const RxDesc) };
        if desc.status & RXD_STAT_DD == 0 {
            return 0;
        }
        // Copy out the payload.
        let len = (desc.length as usize).min(out.len()).min(RX_BUF_LEN);
        let buf_phys = desc.addr;
        // SAFETY: identity-mapped DMA buffer.
        for i in 0..len {
            out[i] = unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) };
        }
        // Rearm the descriptor: clear status, leave addr as-is.
        let new_desc = RxDesc {
            addr: buf_phys,
            length: 0,
            csum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut RxDesc, new_desc);
        }
        // Bump RDT to the just-freed slot. After consuming descriptor
        // `head`, the most recently freed slot is `head` itself —
        // RDT points at the last available slot for the device.
        let new_head = ((head + 1) % RX_RING_LEN) as u32;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RDT, head as u32);
        }
        *head_g = new_head;
        let _ = RXD_STAT_EOP; // EOP-multi-descriptor frames land in a follow-up.
        len
    }

    /// `true` if at least one RX descriptor has its DD bit set.
    /// Cheaper than `rx_recv` when callers want to poll without
    /// consuming.
    pub fn rx_has_pending(&self) -> bool {
        let head = (*self.rx_head.lock()) as usize;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (head * 16) as u64;
        // SAFETY: identity-mapped DMA ring.
        let status = unsafe { core::ptr::read_volatile((desc_addr + 12) as *const u8) };
        status & RXD_STAT_DD != 0
    }

    /// Read CTRL register — useful for tests + diagnostics.
    pub fn read_ctrl(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_CTRL) }
    }

    /// Read STATUS register.
    pub fn read_status(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_STATUS) }
    }

    /// Read IMS (Interrupt Mask Set/Read, 8254x SDM §13.4.20). A
    /// non-zero value indicates IRQ-driven completion is armed.
    pub fn read_ims(&self) -> u32 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read32(REG_IMS) }
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<E1000>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // Enable MEM_SPACE + BUS_MASTER. Leave the legacy INTx path
    // open here — `bring_up` flips INTX_DISABLE on once it has
    // negotiated MSI-X. If we set INTX_DISABLE up front, the INTx
    // fallback can't deliver.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over device.
    let dev = match unsafe { E1000::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let mac = dev.mac;
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(device.id.device)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    // Register with the kernel-side TCP stack: hands the stack a
    // `(mac, send_fn)` pair and a name. The RX-drain hook lets
    // kernel-side busy-wait paths (ARP / TCP handshake) pull
    // frames off the NIC ring directly while spinning, since the
    // spawned RX-pump task can't run while a syscall is parked
    // in `responsive_spin_until`.
    narf_net::iface::register("eth0", mac, e1000_send_frame);
    narf_net::iface::install_rx_drain(rx_pump_step);
    Ok(())
}

/// SendFn registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through E1000::tx.
fn e1000_send_frame(frame: &[u8]) -> Result<(), ()> {
    let g = CONTROLLER.lock();
    let ctrl = g.as_ref().ok_or(())?;
    ctrl.tx(frame).map_err(|_| ())
}

/// Drain one frame from the RX ring + dispatch it through the
/// network stack's RX handler. Returns true iff a frame was
/// processed. Called from a kernel-side polling task spawned at
/// boot.
pub fn rx_pump_step() -> bool {
    let mut buf = [0u8; 1600];
    let n = {
        let g = CONTROLLER.lock();
        match g.as_ref() {
            Some(c) => c.rx_recv(&mut buf),
            None => 0,
        }
    };
    if n == 0 {
        return false;
    }
    narf_net::iface::on_rx_frame(&buf[..n]);
    true
}

/// Register the driver against every Intel device id we recognise.
/// One match per id pair so each is independently maintainable.
pub fn register_pci_driver() {
    for did in [
        E1000_DEV_82540EM,
        E1000_DEV_82545EM,
        E1000_DEV_82544GC,
        E1000E_DEV_82574L,
        E1000E_DEV_I217LM,
    ] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: E1000_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        E1000_DEV_82540EM => "e1000-82540em",
        E1000_DEV_82545EM => "e1000-82545em",
        E1000_DEV_82544GC => "e1000-82544gc",
        E1000E_DEV_82574L => "e1000e-82574l",
        E1000E_DEV_I217LM => "e1000e-i217lm",
        _ => "e1000",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&E1000) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// IRQ-driven RX. Constructs the `wait_for_irq` future *before*
/// inspecting the ring (so an IRQ that lands between the ring drain
/// and the await still wakes us — the future snapshots fire-count
/// at construction). On wake, drains one frame into `out` and
/// returns the byte count. Returns 0 if no controller is bound or
/// no IRQ vector is wired (caller should fall back to `rx_recv`).
pub async fn rx_async(out: &mut [u8]) -> usize {
    let vector = match CONTROLLER.lock().as_ref().and_then(|c| c.irq_vector) {
        Some(v) => v,
        None => return 0,
    };
    // Construct the wait future *before* we look at the ring. The
    // future captures the current fire-count as its baseline; if an
    // RX IRQ fires while we're inside `rx_recv`, the future resolves
    // immediately on next poll (wait_for_irq doc: "construct BEFORE
    // the action that triggers the IRQ").
    let waiter = narf_interrupts::wait::wait_for_irq(vector);
    // Fast path: there might already be a frame ready (e.g. an IRQ
    // landed before we got here). Drain it without awaiting.
    if let Some(n) = with_controller(|c| {
        if c.rx_has_pending() {
            Some(c.rx_recv(out))
        } else {
            None
        }
    })
    .flatten()
    {
        // Cancel the waiter — clear_waker fires in its Drop.
        drop(waiter);
        return n;
    }
    // Slow path: await the next RX IRQ, then drain.
    let _ = waiter.await;
    with_controller(|c| c.rx_recv(out)).unwrap_or(0)
}

/// IRQ-driven TX. Posts `frame` to the TX ring then awaits TXDW.
/// Mirrors the polled `tx` semantics (one frame per call) but parks
/// the caller on the IRQ instead of spinning on DD. Falls back to
/// the polled `tx` path if no IRQ vector is wired.
pub async fn tx_async(frame: &[u8]) -> Result<(), E1000Error> {
    let vector = match CONTROLLER.lock().as_ref().and_then(|c| c.irq_vector) {
        Some(v) => v,
        None => {
            // No IRQ wired — synchronous path is the only option.
            return with_controller(|c| c.tx(frame)).unwrap_or(Err(E1000Error::UnsupportedDevice));
        }
    };
    // Construct the future first, then enqueue. If the device
    // completes before we await, the post-enqueue fire-count check
    // inside `WaitForIrq::poll` resolves immediately.
    let waiter = narf_interrupts::wait::wait_for_irq(vector);
    let slot =
        match with_controller(|c| c.tx_enqueue(frame)).unwrap_or(Err(E1000Error::UnsupportedDevice))
        {
            Ok(s) => s,
            Err(e) => {
                drop(waiter);
                return Err(e);
            }
        };
    // Await the pre-enqueue waiter, then loop on additional IRQs in
    // case the wake was for a different cause (e.g. RXT0) and our
    // slot's DD bit isn't yet set.
    let _ = waiter.await;
    while !with_controller(|c| c.tx_slot_done(slot)).unwrap_or(false) {
        let _ = narf_interrupts::wait::wait_for_irq(vector).await;
    }
    Ok(())
}
