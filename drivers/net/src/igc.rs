//! Intel I225 / I226 family — 2.5 GbE — clean-room.
//!
//! Spec: Intel **"Ethernet Controller I225 Datasheet"** rev 1.4
//! (free PDF, intel.com — public release in March 2021) and the
//! follow-on **"Ethernet Controller I226 Datasheet"** rev 1.0
//! (June 2022). Both expose the same Foxville-family register
//! layout the original `e1000` software-developer's manual
//! describes — the I225 datasheet calls out per-block deltas
//! (advanced TX/RX descriptors, EEC vs EERD, 2.5 GbE PCS) but the
//! basic CTRL / STATUS / RAL / RAH / TCTL / RCTL / TDBAL / RDBAL
//! addresses are unchanged.
//!
//! Stage cut: bring up the controller far enough to read the MAC
//! address out of RAL/RAH, program a TX + RX legacy-descriptor
//! ring (the I225 supports the same legacy descriptor format on
//! top of the advanced one — we use legacy for clean-room
//! simplicity), and expose `tx(&[u8])` + `rx(&mut [u8])`. MSI-X +
//! advanced descriptors land in a follow-up.
//!
//! Register map subset (BAR0 + offset, all 4-byte aligned). The
//! offsets that differ from the base `e1000` driver are noted.
//!
//! | offset  | name | description                          |
//! |---------|------|--------------------------------------|
//! | 0x0000  | CTRL | Device Control                       |
//! | 0x0008  | STATUS | Device Status                      |
//! | 0x0010  | EEC  | EEPROM/Flash Control (I225 specific) |
//! | 0x0014  | EERD | EEPROM Read                          |
//! | 0x00D0  | IMS  | Interrupt Mask Set/Read              |
//! | 0x0100  | RCTL | Receive Control                      |
//! | 0x0400  | TCTL | Transmit Control                     |
//! | 0x2800  | RDBAL/H/LEN/H/T as e1000              |
//! | 0x3800  | TDBAL/H/LEN/H/T as e1000              |
//! | 0x5400  | RAL0 | Receive Address Low                  |
//! | 0x5404  | RAH0 | Receive Address High + Address Valid |

use core::sync::atomic::{compiler_fence, AtomicU64, Ordering};

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Mirrors Linux's `igc_pci_tbl[]` in
// `drivers/net/ethernet/intel/igc/igc_main.c`. The I225 + I226
// families ship in Comet Lake / Tiger Lake / Alder Lake / Raptor
// Lake laptops as discrete 2.5G NICs and on docks; I220-V and I221-V
// are 1G "Foxville-Lite" variants on the same silicon. Stepping
// variants (LMVP / K / K2) appear on Intel NUC and embedded
// platforms. BLANK_NVM IDs are the boot-time fallback when the NVM
// hasn't been programmed (we still bind so the user can flash).

pub const IGC_VENDOR: u16 = 0x8086;

/// I225-LM (LAN-on-motherboard variant).
pub const IGC_I225_LM: u16 = 0x15F2;
/// I225-V (vPro variant).
pub const IGC_I225_V: u16 = 0x15F3;
/// I225-IT (industrial-temp).
pub const IGC_I225_IT: u16 = 0x0D9F;
/// I225-I (server / iLM).
pub const IGC_I225_I: u16 = 0x15F8;
/// I220-V (1 GbE Foxville-Lite).
pub const IGC_I220_V: u16 = 0x15F7;
/// I225-K — NUC / embedded.
pub const IGC_I225_K: u16 = 0x3100;
/// I225-K2 — NUC stepping.
pub const IGC_I225_K2: u16 = 0x3101;
/// I225-LMVP — vPro stepping.
pub const IGC_I225_LMVP: u16 = 0x5502;
/// I225 blank NVM — boot fallback.
pub const IGC_I225_BLANK_NVM: u16 = 0x15FD;
/// I226-LM (LAN-on-motherboard).
pub const IGC_I226_LM: u16 = 0x125B;
/// I226-V.
pub const IGC_I226_V: u16 = 0x125C;
/// I226-IT.
pub const IGC_I226_IT: u16 = 0x125D;
/// I226-K — NUC / embedded.
pub const IGC_I226_K: u16 = 0x3102;
/// I226-LMVP — vPro stepping.
pub const IGC_I226_LMVP: u16 = 0x5503;
/// I226 blank NVM — boot fallback.
pub const IGC_I226_BLANK_NVM: u16 = 0x125F;
/// I221-V (1 GbE).
pub const IGC_I221_V: u16 = 0x125E;

// ── Register offsets ────────────────────────────────────────────────

const REG_CTRL: u64 = 0x0000;
const REG_STATUS: u64 = 0x0008;
/// IGC ICR — Interrupt Cause Read. Reading clears all pending cause
/// bits (Linux `drivers/net/ethernet/intel/igc/igc_defines.h::IGC_ICR`).
const REG_ICR: u64 = 0x00C0;
const REG_IMS: u64 = 0x00D0;
/// IGC IMC — Interrupt Mask Clear (write-1-to-clear).
const REG_IMC: u64 = 0x00D8;
/// IGC GPIE — General Purpose Interrupt Enable. Bit 4 (NSICR) +
/// bit 31 (PBA_support) tell the chip to deliver IRQs as MSI-X
/// rather than legacy IMS (Linux `igc_defines.h::IGC_GPIE`).
const REG_GPIE: u64 = 0x1514;
/// IGC IVAR_MISC — table mapping "other" causes to MSI-X vector
/// number (Linux: `IGC_IVAR_MISC`). We pin the "other" causes to
/// vector index 0 in single-vector MSI-X mode.
const REG_IVAR_MISC: u64 = 0x1740;
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
const CTRL_SLU: u32 = 1 << 6;

// IMS/ICR cause bits. Linux: `IGC_IMS_TXDW`, `IGC_IMS_LSC`,
// `IGC_IMS_RXO`, `IGC_IMS_RXDMT0`, `IGC_IMS_RXT0` from
// `drivers/net/ethernet/intel/igc/igc_defines.h`. Same bit positions
// as the legacy e1000 mask — igc kept the legacy IMS register
// layout for non-MSI-X delivery and single-vector MSI-X uses the
// same cause encoding.
pub const IMS_TXDW: u32 = 1 << 0;
pub const IMS_LSC: u32 = 1 << 2;
pub const IMS_RXO: u32 = 1 << 6;
pub const IMS_RXDMT0: u32 = 1 << 4;
pub const IMS_RXT0: u32 = 1 << 7;
pub const IMS_DEFAULT: u32 = IMS_TXDW | IMS_LSC | IMS_RXO | IMS_RXDMT0 | IMS_RXT0;

// GPIE bits. Single-vector MSI-X needs GPIE.NSICR set so the chip
// stops auto-clearing the entire ICR on read (we want the "extended"
// MSI-X cause encoding) and GPIE.MULTIPLE_MSIX set so the chip
// honours per-cause IVAR routing.
pub const GPIE_NSICR: u32 = 1 << 0;
pub const GPIE_MULTIPLE_MSIX: u32 = 1 << 4;
pub const GPIE_EIAME: u32 = 1 << 30;
pub const GPIE_PBA: u32 = 1 << 31;

// TCTL bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

// RCTL bits.
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15; // Broadcast accept.
const RCTL_BSIZE_2K: u32 = 0; // bits[17:16] = 0 → 2 KiB

// TX descriptor flags.
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1;
const TXD_CMD_RS: u8 = 1 << 3;
const TXD_STAT_DD: u8 = 1 << 0;

// Ring sizes — small but valid (must be a multiple of 8 per
// I225 datasheet §7.2.7).
const TX_RING_LEN: usize = 8;
const RX_RING_LEN: usize = 8;
const FRAME_SIZE: usize = 2048;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IgcError {
    BarMapFailed,
    ResetTimeout,
    QueueTooSmall,
}

/// MMIO base of the IRQ-attached IGC, shared with the static ISR so
/// it can read ICR (read-to-clear per `IGC_ICR` docs) and acknowledge
/// the device. 0 = no controller bound (handler short-circuits).
///
/// Single-controller invariant matches the rest of the driver:
/// `CONTROLLER` is a single `Option<Igc>` slot below.
static ISR_MMIO_BASE: AtomicU64 = AtomicU64::new(0);

/// Sync ISR: read ICR to acknowledge the device, then return. The
/// dispatch layer (`narf_interrupts::dispatch::on_irq`) bumps the
/// per-vector fire-count and wakes any waiter. We keep the polled
/// `tx`/`rx` paths regardless so bring-up tests work in the no-IRQ
/// environment.
///
/// MSI-X is edge-triggered and the read of ICR is a no-op for the
/// edge case, but it's safe to issue and matches what Linux does in
/// `igc_intr` regardless of MSI-X vs legacy delivery.
fn igc_isr() {
    let base = ISR_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: `base` is the device's BAR0 phys, identity-mapped at
    // bring-up; ICR (offset 0xC0) is inside the IGC register window.
    unsafe {
        let _icr = narf_arch::mmio::read32(base + REG_ICR);
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct LegacyTxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    sta: u8,
    css: u8,
    special: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct LegacyRxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

pub struct Igc {
    mmio: MmioRegion,
    mac: [u8; 6],
    tx_ring_buf: DmaBuffer,
    rx_ring_buf: DmaBuffer,
    rx_buf_pool: alloc::vec::Vec<DmaBuffer>,
    tx_buf: DmaBuffer,
    tx_tail: IrqSafeSpinLock<u16>,
    rx_head: IrqSafeSpinLock<u16>,
    pub ready: bool,
    /// MSI-X table mapping when MSI-X is enabled. Holds the table
    /// alive for the device lifetime; dropping it would unmap the
    /// MSI-X BAR.
    _msix: Option<MsixTable>,
    /// IDT vector bound to the device's MSI-X table[0]. `None`
    /// means we fell back to polled-only completion.
    pub irq_vector: Option<u8>,
}

impl core::fmt::Debug for Igc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Igc")
            .field("mac", &self.mac)
            .field("ready", &self.ready)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl Igc {
    /// Bring up the controller.
    ///
    /// # Safety
    /// Caller owns BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, IgcError> {
        // SAFETY: caller-asserted.
        let mmio = unsafe { map_bar(device, 0) }.map_err(|_| IgcError::BarMapFailed)?;

        // 1. Master reset.
        // SAFETY: identity-mapped MMIO.
        let ctrl = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, ctrl | CTRL_RST);
        }
        // SAFETY: identity-mapped MMIO; responsive_spin_until ticks
        // sleep_pumps so FB cursor / serial drain stay alive on a
        // slow reset. Intel I225 datasheet §8.2.3.1: CTRL.RST self-
        // clears within ~10 ms; 100 ms is the wedge threshold.
        narf_scheduler::responsive_spin_until(
            || unsafe { mmio.read32(REG_CTRL) } & CTRL_RST == 0,
            narf_time::Deadline::after_ms(100),
        );
        // SAFETY: same.
        let after = unsafe { mmio.read32(REG_CTRL) };
        if after & CTRL_RST != 0 {
            return Err(IgcError::ResetTimeout);
        }

        // 2. Mask all interrupt causes during bring-up. IMC is
        //    write-1-to-clear (Linux: IGC_IMC); writing all-ones
        //    leaves IMS = 0 and prevents stale IRQs while we program
        //    the rings. Re-enabled in step 8 once MSI-X is bound.
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_IMC, !0u32);
            // Clear any pending causes by reading ICR (read-to-clear).
            let _ = mmio.read32(REG_ICR);
        }

        // 3. Set link up.
        // SAFETY: same.
        let ctrl = unsafe { mmio.read32(REG_CTRL) };
        // SAFETY: same.
        unsafe {
            mmio.write32(REG_CTRL, ctrl | CTRL_SLU);
        }

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
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IgcError::BarMapFailed)?;
        let rx_ring_buf =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| IgcError::BarMapFailed)?;
        let tx_buf =
            alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0).map_err(|_| IgcError::BarMapFailed)?;
        let mut rx_buf_pool: alloc::vec::Vec<DmaBuffer> =
            alloc::vec::Vec::with_capacity(RX_RING_LEN);
        for _ in 0..RX_RING_LEN {
            rx_buf_pool.push(
                alloc_coherent(FRAME_SIZE, DomainId::DRIVER_0)
                    .map_err(|_| IgcError::BarMapFailed)?,
            );
        }

        // 6. Initialise TX descriptors (zeroed by alloc_coherent).
        let tx_phys = tx_ring_buf.phys_addr().raw();
        let tx_len = (TX_RING_LEN * 16) as u32;
        // SAFETY: identity-mapped DMA, freshly zeroed.
        unsafe {
            mmio.write32(REG_TDBAL, (tx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(REG_TDBAH, (tx_phys >> 32) as u32);
            mmio.write32(REG_TDLEN, tx_len);
            mmio.write32(REG_TDH, 0);
            mmio.write32(REG_TDT, 0);
            mmio.write32(REG_TCTL, TCTL_EN | TCTL_PSP);
        }

        // 7. Initialise RX descriptors with our pre-allocated frames.
        let rx_phys = rx_ring_buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA, freshly zeroed.
        unsafe {
            for i in 0..RX_RING_LEN {
                let desc = (rx_phys + (i * 16) as u64) as *mut LegacyRxDesc;
                core::ptr::write_volatile(
                    desc,
                    LegacyRxDesc {
                        addr: rx_buf_pool[i].phys_addr().raw(),
                        ..Default::default()
                    },
                );
            }
            mmio.write32(REG_RDBAL, (rx_phys & 0xFFFF_FFFF) as u32);
            mmio.write32(REG_RDBAH, (rx_phys >> 32) as u32);
            mmio.write32(REG_RDLEN, (RX_RING_LEN * 16) as u32);
            mmio.write32(REG_RDH, 0);
            mmio.write32(REG_RDT, (RX_RING_LEN - 1) as u32);
            mmio.write32(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2K);
        }

        // 8. Try MSI-X (single vector covering all causes). Linux's
        //    `igc_request_irq` uses MSI-X with separate per-queue
        //    vectors; we collapse to one vector at Stage-2 (mirrors
        //    e1000.rs's approach). Polling stays as the fallback so
        //    bring-up tests work without an IRQ vector.
        let (msix, irq_vector) = match Self::try_enable_msix(cap, device) {
            Ok((tbl, v)) => (Some(tbl), Some(v)),
            Err(_) => (None, None),
        };

        // Publish MMIO base for the static ISR before installing the
        // handler so an early MSI-X delivery can't find a zero base.
        if irq_vector.is_some() {
            ISR_MMIO_BASE.store(mmio.phys.raw(), Ordering::Release);
        }
        if let Some(v) = irq_vector {
            narf_interrupts::install_handler(v, igc_isr);
        }

        // 9. Program GPIE for single-vector MSI-X delivery. Linux:
        //    `igc_configure_msix` — sets GPIE.NSICR + MULTIPLE_MSIX +
        //    EIAME + PBA so MSI-X delivery + ICR semantics agree.
        //    Then unmask the standard RX/TX/LSC/RXO cause set in IMS.
        //    Skip if no IRQ vector was bound — keep "all masked" so
        //    polled callers don't see spurious cause bits.
        if irq_vector.is_some() {
            // SAFETY: identity-mapped MMIO.
            unsafe {
                mmio.write32(
                    REG_GPIE,
                    GPIE_NSICR | GPIE_MULTIPLE_MSIX | GPIE_EIAME | GPIE_PBA,
                );
                // Route the "other" causes (link-status etc) to MSI-X
                // table[0]. Single-vector mode pins everything at
                // index 0. IVAR_MISC bit 7 is the valid bit for the
                // low byte; vector index lives in bits[6:0].
                mmio.write32(REG_IVAR_MISC, 0x0000_0080);
                mmio.write32(REG_IMS, IMS_DEFAULT);
            }
            // INTX_DISABLE is already set by the probe path (igc has
            // no INTx fallback wired — we depend on MSI-X or
            // polling). No PCI Command write needed here.
        }

        Ok(Self {
            mmio,
            mac,
            tx_ring_buf,
            rx_ring_buf,
            rx_buf_pool,
            tx_buf,
            tx_tail: IrqSafeSpinLock::new(0),
            rx_head: IrqSafeSpinLock::new(0),
            ready: true,
            _msix: msix,
            irq_vector,
        })
    }

    /// Walk the controller's MSI-X capability, allocate an IDT vector
    /// + table slot, program slot 0 to deliver to BSP, and flip the
    /// global MSI-X enable. Returns `(table, vector)` on success.
    /// Failure leaves the device in polled-only mode (we don't have
    /// an INTx fallback for igc — Linux's igc driver requires MSI-X
    /// in modern kernels too).
    ///
    /// Linux equivalent: `igc_request_irq` →
    /// `pci_enable_msix_range(adapter->pdev, ..., msix_vectors=N)`
    /// (`drivers/net/ethernet/intel/igc/igc_main.c`).
    fn try_enable_msix(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<(MsixTable, u8), IgcError> {
        let mut msix = enable_msix(cap, device).map_err(|_| IgcError::BarMapFailed)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| IgcError::BarMapFailed)?;
        let _ = msix.alloc_vector().ok_or(IgcError::BarMapFailed)?;
        // Deliver to APIC id 0 (BSP). On aarch64 this routes through
        // the GIC ITS doorbell with EventID=v.
        // SAFETY: caller holds the BusDeviceCap; we own the MSI-X
        // table (no other writer); we issue this write before the
        // global enable so the device can't fire stale data.
        let _ = unsafe { msix.program_vector(0, 0, v) }
            .map_err(|_| IgcError::BarMapFailed)?;
        // SAFETY: cfg-space write to a known cap-list offset.
        let _ = unsafe { msix.enable() }.map_err(|_| IgcError::BarMapFailed)?;
        Ok((msix, v))
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        // SAFETY: identity-mapped MMIO; STATUS bit 1 = LU (link up).
        let s = unsafe { self.mmio.read32(REG_STATUS) };
        s & (1 << 1) != 0
    }

    /// Transmit a single Ethernet frame. Polls the descriptor's
    /// Done bit. Frame must fit in `FRAME_SIZE`.
    pub fn tx(&self, frame: &[u8]) -> Result<(), IgcError> {
        if frame.is_empty() || frame.len() > FRAME_SIZE {
            return Err(IgcError::QueueTooSmall);
        }
        let buf_phys = self.tx_buf.phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((buf_phys + i as u64) as *mut u8, *b);
            }
        }
        let mut tail = self.tx_tail.lock();
        let idx = *tail as usize;
        let ring_phys = self.tx_ring_buf.phys_addr().raw();
        let desc = (ring_phys + (idx * 16) as u64) as *mut LegacyTxDesc;
        // SAFETY: identity-mapped DMA, idx < TX_RING_LEN.
        unsafe {
            core::ptr::write_volatile(
                desc,
                LegacyTxDesc {
                    addr: buf_phys,
                    length: frame.len() as u16,
                    cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
                    ..Default::default()
                },
            );
        }
        let next = ((idx + 1) % TX_RING_LEN) as u16;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TDT, next as u32);
        }
        // Poll for Done bit. responsive_spin_until ticks sleep_pumps.
        // 250 ms wall-clock budget covers a worst-case Tx-side
        // congestion stall on a single packet.
        let done = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA.
            || unsafe { core::ptr::read_volatile((desc as *const u8).add(12)) } & TXD_STAT_DD != 0,
            narf_time::Deadline::after_ms(250),
        );
        if !done {
            return Err(IgcError::ResetTimeout);
        }
        *tail = next;
        Ok(())
    }

    /// Receive a single frame; returns the byte count copied into
    /// `out`, or 0 if no frame is currently available.
    pub fn rx(&self, out: &mut [u8]) -> usize {
        let mut head = self.rx_head.lock();
        let idx = *head as usize;
        let ring_phys = self.rx_ring_buf.phys_addr().raw();
        let desc_ptr = (ring_phys + (idx * 16) as u64) as *mut LegacyRxDesc;
        // SAFETY: identity-mapped DMA.
        let desc = unsafe { core::ptr::read_volatile(desc_ptr) };
        // RX status DD bit (bit 0). Vendor docs reuse the e1000
        // convention.
        if desc.status & 0x01 == 0 {
            return 0;
        }
        let len = (desc.length as usize).min(out.len());
        let buf_phys = self.rx_buf_pool[idx].phys_addr().raw();
        // SAFETY: identity-mapped DMA.
        for i in 0..len {
            out[i] = unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) };
        }
        // Refill descriptor: clear status + length + bump tail.
        let new_desc = LegacyRxDesc {
            addr: buf_phys,
            ..Default::default()
        };
        // SAFETY: identity-mapped DMA.
        unsafe {
            core::ptr::write_volatile(desc_ptr, new_desc);
        }
        let next = ((idx + 1) % RX_RING_LEN) as u16;
        *head = next;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            self.mmio.write32(REG_RDT, ((idx) % RX_RING_LEN) as u32);
        }
        len
    }
}

// ── HwNic adapter ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct IgcNic;

impl crate::HwNic for IgcNic {
    fn name(&self) -> &'static str {
        "igc"
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
        crate::NicCaps::NONE
    }
    fn ring_capacity(&self) -> usize {
        TX_RING_LEN
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Igc>> = IrqSafeSpinLock::new(None);

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
    let dev = match unsafe { Igc::bring_up(&device, &cap) } {
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

/// Every Intel device id this driver claims. Kept as a single
/// `const` so the `register_pci_driver` loop and the match-table
/// smoke test see the same list (no drift between code + test).
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    IGC_I225_LM,
    IGC_I225_V,
    IGC_I225_IT,
    IGC_I225_I,
    IGC_I220_V,
    IGC_I225_K,
    IGC_I225_K2,
    IGC_I225_LMVP,
    IGC_I225_BLANK_NVM,
    IGC_I226_LM,
    IGC_I226_V,
    IGC_I226_IT,
    IGC_I226_K,
    IGC_I226_LMVP,
    IGC_I226_BLANK_NVM,
    IGC_I221_V,
];

pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: IGC_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

fn name_for(did: u16) -> &'static str {
    match did {
        IGC_I225_LM => "igc-i225-lm",
        IGC_I225_V => "igc-i225-v",
        IGC_I225_IT => "igc-i225-it",
        IGC_I225_I => "igc-i225-i",
        IGC_I220_V => "igc-i220-v",
        IGC_I225_K => "igc-i225-k",
        IGC_I225_K2 => "igc-i225-k2",
        IGC_I225_LMVP => "igc-i225-lmvp",
        IGC_I225_BLANK_NVM => "igc-i225-blank-nvm",
        IGC_I226_LM => "igc-i226-lm",
        IGC_I226_V => "igc-i226-v",
        IGC_I226_IT => "igc-i226-it",
        IGC_I226_K => "igc-i226-k",
        IGC_I226_LMVP => "igc-i226-lmvp",
        IGC_I226_BLANK_NVM => "igc-i226-blank-nvm",
        IGC_I221_V => "igc-i221-v",
        _ => "igc",
    }
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&Igc) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
