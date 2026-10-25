//! AHCI HBA driver (Intel ICH9 + compatible).
//!
//! Spec: AHCI 1.3.1 — Serial ATA Advanced Host Controller Interface.
//! <https://www.intel.com/content/www/us/en/io/serial-ata/serial-ata-ahci-spec-rev1-3-1.html>
//!
//! Interrupt model (this revision):
//! - HBA `GHC.IE` (bit 1) is the master "deliver any interrupt" gate
//!   (§3.1.2). When clear no port-level IRQ ever leaves the HBA.
//! - Per-port `PORT_IE` (offset +0x14) selects which events on a port
//!   raise the port's bit in HBA `IS` (§3.3.6). We unmask the
//!   completion-bearing events: D2H Register FIS (bit 0), PIO Setup
//!   (bit 1), DMA Setup (bit 2), plus Task File Error (bit 30) so a
//!   failing command doesn't sit unnoticed.
//! - The ISR walks HBA `IS` to find ports with pending events
//!   (§3.1.3), drains each port's `PORT_IS` (W1C), then clears the
//!   port bit in HBA `IS` (also W1C).
//! - `narf_interrupts::on_irq` (called from the registered sync
//!   handler via the dispatch table) bumps a per-vector `fire_count`
//!   and wakes any task awaiting `wait_for_irq`. Async I/O paths
//!   (`*_async`) construct the wait future BEFORE writing PORT_CI so
//!   they cannot race the IRQ.
//!
//! QEMU's q35 AHCI controller is at `8086:2922` (00:1f.2 by default);
//! ICH9 family.
//!
//! HBA register layout (BAR5 = ABAR, MMIO):
//!
//! | offset  | name | description                       |
//! |---------|------|-----------------------------------|
//! | 0x00    | CAP  | HBA Capabilities                  |
//! | 0x04    | GHC  | Global Host Control               |
//! | 0x08    | IS   | Interrupt Status                  |
//! | 0x0C    | PI   | Ports Implemented (bitmap)        |
//! | 0x10    | VS   | AHCI Version                      |
//! | 0x100   | port[0]                                |
//! | 0x180   | port[1]                                |
//! | 0x200   | port[2]                                |
//! | ...                                              |
//!
//! Per-port (offset = 0x100 + 0x80 * n):
//!
//! | offset  | name  | description                     |
//! |---------|-------|---------------------------------|
//! | +0x00   | CLB   | Command List Base Low           |
//! | +0x04   | CLBU  | Command List Base High          |
//! | +0x08   | FB    | FIS Base Low                    |
//! | +0x0C   | FBU   | FIS Base High                   |
//! | +0x10   | IS    | Interrupt Status                |
//! | +0x14   | IE    | Interrupt Enable                |
//! | +0x18   | CMD   | Command and Status              |
//! | +0x20   | TFD   | Task File Data                  |
//! | +0x24   | SIG   | Signature (after spin-up)       |
//! | +0x28   | SSTS  | SATA Status                     |
//! | +0x2C   | SCTL  | SATA Control                    |
//! | +0x30   | SERR  | SATA Error                      |
//! | +0x34   | SACT  | SATA Active                     |
//! | +0x38   | CI    | Command Issue                   |

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::req_gate::ReqGate;

use narf_bus::{enable_msix, map_bar, BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};

/// Size of the per-controller bulk-transfer DMA buffer (#930).
/// The block path chunks requests at this size: 128 KiB = 256
/// sectors per command, carried by a single PRDT entry (the PRDT
/// byte-count field tops out at 4 MiB).
pub const AHCI_XFER_BYTES: usize = 128 * 1024;

/// A DMA staging region for one transfer: the physical address of
/// a coherent region and how many of its bytes the transfer may
/// use. Either the scratch page's data area (small transfers) or
/// the per-controller transfer buffer (bulk, #930).
#[derive(Copy, Clone, Debug)]
pub struct DmaStage {
    pub phys: u64,
    pub cap: usize,
}

/// Allocate (once) and return the physical address of one of a
/// controller's persistent DMA buffers — its 4 KiB command scratch
/// or its bulk-transfer buffer. Buffers are PER-CONTROLLER state
/// (#931): two HBAs must never share command structures or a
/// transfer buffer, so what used to be one global scratch (audit
/// #3's fix for per-call alloc/free churn) is now a field of
/// [`Ahci`]. Layout of the scratch page matches the per-call
/// buffers: cmd_list@0x000, fis_recv@0x400, cmd_tbl@0x500,
/// data_buf@0x600 (offsets used by every path below).
///
/// An HBA without CAP.S64A drops the upper address dwords (Linux
/// sets a 32-bit DMA mask for it), so the buffer is allocated
/// through `alloc_coherent_masked` with a 32-bit mask for such
/// controllers. Returns 0 only on allocation failure (call sites
/// treat it as a programming error via debug_assert, matching the
/// pre-DmaBuffer behaviour).
fn persistent_dma_phys(slot: &IrqSafeSpinLock<Option<DmaBuffer>>, cap: u32, bytes: usize) -> u64 {
    let mut g = slot.lock();
    if g.is_none() {
        let mask = if cap & CAP_S64A != 0 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        *g = narf_io::alloc_coherent_masked(bytes, DomainId::DRIVER_0, mask).ok();
    }
    let phys = g.as_ref().map(|b| b.dma_addr().raw()).unwrap_or(0);
    debug_assert!(phys != 0, "AHCI persistent DMA allocation failed");
    phys
}

/// Byte offset of the data area inside the shared 4 KiB scratch
/// (cmd_list@0x000, fis_recv@0x400, cmd_tbl@0x500, data@0x600).
const SCRATCH_DATA_OFF: usize = 0x600;

/// Payload bytes the scratch's own data area can hold past the
/// command structures: `4096 - 0x600` = 2560 bytes = 5 sectors.
/// Transfers that stay inside the scratch page are capped here;
/// the block path's bulk transfers point the PRDT at the separate
/// per-controller transfer buffer instead (#930). The cap matters:
/// the previous per-path checks allowed 8 sectors (4096 payload
/// bytes) against this 2560-byte area, which let both the host-side
/// zeroing and the device's PRDT DMA run up to 1536 bytes past the
/// end of the page into whatever the allocator placed next — an
/// out-of-bounds write reachable from any ≥6-sector registry read.
const SCRATCH_DATA_MAX: usize = 4096 - SCRATCH_DATA_OFF;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

pub const AHCI_VENDOR: u16 = 0x8086;
/// QEMU q35 ICH9 AHCI.
pub const AHCI_ICH9_DEV: u16 = 0x2922;
/// Real silicon ICH10 AHCI.
pub const AHCI_ICH10_DEV: u16 = 0x3A22;

/// PCI class triple of an AHCI 1.0 SATA controller (`01:06:01`,
/// Linux `PCI_CLASS_STORAGE_SATA_AHCI`). Linux's `ahci_pci_tbl` ends
/// with a generic entry on this class (`board_ahci`), which is what
/// binds controllers with no explicit ID entry — among them the AMD
/// 600-series chipset SATA controller `1022:43f6`.
pub const PCI_CLASS_STORAGE: u8 = 0x01;
/// SATA subclass.
pub const PCI_SUBCLASS_SATA: u8 = 0x06;
/// AHCI 1.0 programming interface.
pub const PCI_PROGIF_AHCI: u8 = 0x01;

/// AMD vendor ID.
pub const AMD_VENDOR: u16 = 0x1022;
/// AMD 600-series chipset SATA controller (Promontory 21). Linux has no
/// explicit `ahci_pci_tbl` entry for it: the generic AHCI class entry
/// binds it with `board_ahci` (no `AHCI_HFLAG_*` quirks, MSI allowed).
/// The only AMD-chipset special case in drivers/ata/ahci.c is a DMI
/// LPM blacklist for one ASUS B550 board (`1022:43eb`), and NARF never
/// enables link power management.
pub const AMD_600_SERIES_SATA_DEV: u16 = 0x43F6;

const ABAR_BAR: u8 = 5;

const HBA_CAP: u64 = 0x00;
const HBA_GHC: u64 = 0x04;
/// HBA Interrupt Status — one bit per port; W1C (AHCI 1.3.1 §3.1.3).
const HBA_IS: u64 = 0x08;
const HBA_PI: u64 = 0x0C;
const HBA_VS: u64 = 0x10;
/// HBA Capabilities Extended (AHCI 1.2+, §3.1.10).
const HBA_CAP2: u64 = 0x24;
/// BIOS/OS Handoff Control and Status (AHCI 1.2+, §3.1.11).
const HBA_BOHC: u64 = 0x28;

// CAP bits (AHCI 1.3.1 §3.1.1).
/// CAP.NP — number of ports, zero-based (bits 4:0).
const CAP_NP_MASK: u32 = 0x1F;
/// CAP.SSS — supports staggered spin-up.
const CAP_SSS: u32 = 1 << 27;
/// CAP.S64A — supports 64-bit addressing.
const CAP_S64A: u32 = 1 << 31;

// CAP2 / BOHC bits.
/// CAP2.BOH — BIOS/OS handoff supported.
const CAP2_BOH: u32 = 1 << 0;
/// BOHC.BOS — BIOS owned semaphore.
const BOHC_BOS: u32 = 1 << 0;
/// BOHC.OOS — OS owned semaphore.
const BOHC_OOS: u32 = 1 << 1;
/// BOHC.BB — BIOS busy.
const BOHC_BB: u32 = 1 << 4;

// GHC bits.
const GHC_HR: u32 = 1 << 0; // HBA Reset
/// GHC.IE — Interrupt Enable, master gate (AHCI 1.3.1 §3.1.2).
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31; // AHCI Enable

// Per-port offsets.
const PORT_BASE_OFF: u64 = 0x100;
const PORT_STRIDE: u64 = 0x80;

/// PORT_IS — port interrupt status; W1C (AHCI 1.3.1 §3.3.5).
const PORT_IS: u64 = 0x10;
/// PORT_IE — port interrupt enable mask (AHCI 1.3.1 §3.3.6).
const PORT_IE: u64 = 0x14;
const PORT_CMD: u64 = 0x18;
const PORT_SIG: u64 = 0x24;
const PORT_SSTS: u64 = 0x28;
/// PORT_SCTL — SATA Control (SCR2): DET field at bits[3:0] (AHCI 1.3.1 §3.3.11).
const PORT_SCTL: u64 = 0x2C;
const PORT_SERR: u64 = 0x30;
/// PORT_CI — Command Issue, written to launch a command (§3.3.14).
const PORT_CI: u64 = 0x38;

/// PORT_SSTS.DET field values (AHCI 1.3.1 §3.3.10 / SATA 3.x §8.1):
///   0 — no device, no PHY.
///   1 — device present but PHY comms not established.
///   3 — device present and PHY comms established (normal run).
pub const SSTS_DET_NO_DEVICE: u32 = 0;
pub const SSTS_DET_NO_COMM: u32 = 1;
pub const SSTS_DET_PRESENT: u32 = 3; // link-up

/// PORT_SSTS.IPM field values (Interface Power Management, bits[11:8]):
///   0 — not present / slumber.
///   1 — active.
///   2 — partial power.
pub const SSTS_IPM_NOT_PRESENT: u32 = 0;
pub const SSTS_IPM_ACTIVE: u32 = 1;

/// Decode PORT_SSTS into `(det, ipm)` nibbles.
#[inline]
pub fn ssts_decode(ssts: u32) -> (u32, u32) {
    (ssts & 0x0F, (ssts >> 8) & 0x0F)
}

// PORT_IE / PORT_IS event bits (AHCI 1.3.1 §3.3.6).
const PIE_D2H_REG_FIS: u32 = 1 << 0; // Device-to-Host Register FIS Interrupt
const PIE_PIO_SETUP_FIS: u32 = 1 << 1; // PIO Setup FIS Interrupt
const PIE_DMA_SETUP_FIS: u32 = 1 << 2; // DMA Setup FIS Interrupt
const PIE_TASK_FILE_ERR: u32 = 1 << 30; // Task File Error Status

/// Mask of port-level events we unmask at bring-up. Anything outside
/// this mask still stays in PORT_IS but does not raise the port's
/// HBA-IS bit, so the ISR won't see it.
const PORT_IE_MASK: u32 =
    PIE_D2H_REG_FIS | PIE_PIO_SETUP_FIS | PIE_DMA_SETUP_FIS | PIE_TASK_FILE_ERR;

// PORT_CMD bits.
const CMD_ST: u32 = 1 << 0; // Start
const CMD_SUD: u32 = 1 << 1; // Spin-Up Device
const CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const CMD_FR: u32 = 1 << 14; // FIS Receive Running
const CMD_CR: u32 = 1 << 15; // Command List Running
/// PxCMD.ICC — Interface Communication Control (bits 31:28).
const CMD_ICC_MASK: u32 = 0xF << 28;
/// ICC = 1: Active.
const CMD_ICC_ACTIVE: u32 = 1 << 28;
/// Platform-defined, write-once port capability bits Linux preserves
/// across an HBA reset (`PORT_CMD_CAP` = HPCP | MPSP | CPD | ESP |
/// FBSCP, drivers/ata/ahci.h).
const CMD_CAP_MASK: u32 = (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22);
/// PORT_TFD — Task File Data (status in bits 7:0).
const PORT_TFD: u64 = 0x20;
/// ATA status BSY.
const ATA_BUSY: u32 = 0x80;

/// Detected device class on a port (from PORT_SIG).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortKind {
    None,
    Sata,  // SIG = 0x00000101
    Atapi, // SIG = 0xEB140101
    Semb,  // SIG = 0xC33C0101
    Pmp,   // SIG = 0x96690101
    Unknown(u32),
}

impl PortKind {
    fn from_sig(sig: u32, ssts: u32) -> Self {
        // SSTS DET bits[3:0] = 3 means device present + comm OK.
        if (ssts & 0x0F) != 3 {
            return PortKind::None;
        }
        match sig {
            0x0000_0101 => PortKind::Sata,
            0xEB14_0101 => PortKind::Atapi,
            0xC33C_0101 => PortKind::Semb,
            0x9669_0101 => PortKind::Pmp,
            other => PortKind::Unknown(other),
        }
    }
}

/// One discovered port.
#[derive(Copy, Clone, Debug)]
pub struct PortInfo {
    pub index: u8,
    pub kind: PortKind,
}

/// ATA feature set decoded from an IDENTIFY DEVICE block (#841).
/// Pure function of the 512-byte block — see
/// [`identify_ata_features`]. All fields describe what the DEVICE
/// reports; whether the driver uses a feature is the driver's
/// business (flush/write_fua/trim consult these).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AtaFeatures {
    /// LBA48 addressing (IDENTIFY word 83 bit 10, with the word's
    /// validity signature). Gates FLUSH CACHE EXT / WRITE DMA EXT.
    pub lba48: bool,
    /// A write cache is present (word 82 bit 5).
    pub write_cache_supported: bool,
    /// A write cache is currently ENABLED (word 85 bit 5): writes
    /// may complete before reaching the medium.
    pub write_cache_enabled: bool,
    /// FLUSH CACHE (0xE7) supported (word 82 bit 12).
    pub flush_cache: bool,
    /// FLUSH CACHE EXT (0xEA) supported (word 83 bit 13).
    pub flush_cache_ext: bool,
    /// WRITE DMA FUA EXT (0x3D) supported (word 84 bit 10).
    pub write_fua_ext: bool,
    /// DATA SET MANAGEMENT (0x06) with the TRIM feature bit
    /// supported (word 169 bit 0).
    pub trim: bool,
    /// Maximum 512-byte blocks per DATA SET MANAGEMENT command
    /// (word 105). 1 when the word reads 0, per the ACS.
    pub dsm_max_blocks: u16,
}

/// Decode the feature words of an IDENTIFY DEVICE block.
/// Words 82–85 carry a validity signature in their top two bits
/// (`01b` = valid); features behind an invalid word are reported
/// as absent, matching libata's `ata_id_has_*` helpers.
pub fn identify_ata_features(id: &[u8; 512]) -> AtaFeatures {
    let word = |n: usize| -> u16 { u16::from_le_bytes([id[2 * n], id[2 * n + 1]]) };
    let w82 = word(82);
    let w83 = word(83);
    let w84 = word(84);
    let w85 = word(85);
    let valid83 = w83 & 0xC000 == 0x4000;
    let valid84 = w84 & 0xC000 == 0x4000;
    let dsm_max = word(105);
    AtaFeatures {
        lba48: valid83 && w83 & (1 << 10) != 0,
        write_cache_supported: w82 & (1 << 5) != 0,
        write_cache_enabled: w82 & (1 << 5) != 0 && w85 & (1 << 5) != 0,
        flush_cache: w82 & (1 << 12) != 0,
        flush_cache_ext: valid83 && w83 & (1 << 13) != 0,
        write_fua_ext: valid84 && w84 & (1 << 10) != 0,
        trim: word(169) & 1 != 0,
        dsm_max_blocks: if dsm_max == 0 { 1 } else { dsm_max },
    }
}

/// One published ATA disk on a controller (#931): everything the
/// block surface, the registry identity, and the suspend/resume
/// revalidation need to know about the disk behind a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskInfo {
    /// Port index on the owning controller.
    pub port: u8,
    /// User-addressable sectors from IDENTIFY DEVICE.
    pub sectors: u64,
    /// Feature set from the same IDENTIFY block.
    pub features: AtaFeatures,
    /// IDENTIFY model string (words 27–46), trimmed.
    pub model: alloc::string::String,
    /// IDENTIFY serial number (words 10–19), trimmed.
    pub serial: alloc::string::String,
    /// IDENTIFY firmware revision (words 23–26), trimmed.
    pub firmware: alloc::string::String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AhciError {
    BarMapFailed,
    /// HBA reset never cleared GHC.HR within the bounded poll.
    ResetTimeout,
    /// PORT_CMD never reported FR + CR cleared so we couldn't safely
    /// reprogram the port.
    PortIdleTimeout,
    /// GHC.AE would not stay set after five writes (Linux
    /// `ahci_enable_ahci` WARNs in the same case).
    AhciEnableFailed,
}

/// Live AHCI HBA. Stage-4 cut keeps just the MMIO + the discovered
/// port list. Per-port command-list / FIS-receive structures are
/// allocated by `claim_port` (a follow-up).
pub struct Ahci {
    mmio: MmioRegion,
    /// Bus address this controller was probed at. The controller
    /// registry deduplicates on it (#931): a repeat probe of the
    /// same function is a no-op, a second HBA installs alongside.
    pub addr: narf_bus::BusAddr,
    pub cap: u32,
    /// CAP2 (zero below AHCI 1.2).
    pub cap2: u32,
    pub vs: u32,
    pub pi: u32,
    pub ports: alloc::vec::Vec<PortInfo>,
    /// Outcome of the BIOS/OS ownership handoff at bring-up.
    pub handoff: BiosHandoff,
    /// Port the registry's `sata0` device addresses (first port that
    /// classified as an ATA disk; port 0 if none did).
    pub block_port: u8,
    /// User-addressable sectors on `block_port` from IDENTIFY DEVICE
    /// (LBA48 words 100..103, else LBA28 words 60..61); 0 if unknown.
    pub capacity: u64,
    /// Per-port FIS receive areas used during the link bring-up
    /// (and the shared, never-issued command list they point at).
    /// Kept for the HBA's lifetime: a port may post a FIS late.
    _init_dma: Option<DmaBuffer>,
    /// Serialises synchronous transfers (and this controller's
    /// scratch / transfer-buffer contents) across callers. Spun on
    /// WITHOUT masking interrupts — see
    /// [`crate::req_gate::ReqGate`] for why this replaces holding
    /// the controller lock across a 30-second-budget CI/D2H poll.
    req_gate: AtomicBool,
    /// This controller's persistent 4 KiB command scratch
    /// (cmd_list@0x000, fis_recv@0x400, cmd_tbl@0x500,
    /// data@0x600), allocated lazily by [`Self::scratch_phys`].
    /// Per-controller since #931 — the pre-#931 single global
    /// scratch would have two HBAs DMA into the same page.
    scratch: IrqSafeSpinLock<Option<DmaBuffer>>,
    /// This controller's persistent bulk-transfer buffer
    /// ([`AHCI_XFER_BYTES`]) for the block path (#930), allocated
    /// lazily by [`Self::xfer_phys`].
    xfer: IrqSafeSpinLock<Option<DmaBuffer>>,
    /// Disks published for this controller, one per ATA-disk port
    /// (#931). Filled at probe from per-port IDENTIFY; the
    /// suspend/resume path revalidates against it (#932).
    disks: IrqSafeSpinLock<alloc::vec::Vec<DiskInfo>>,
    /// True between the device_pm suspend handler quiescing this
    /// controller and the resume handler revalidating it (#932).
    /// The block surface refuses I/O with `DeviceRemoved` while set.
    suspended: AtomicBool,
    /// MSI vector the shared ISR serves for this controller, 0 when
    /// this controller has none. Only the FIRST installed HBA gets
    /// the vector: `ahci_isr` + the `AHCI_MMIO_BASE` /
    /// `AHCI_IRQ_VECTOR` globals are a single-controller design;
    /// later HBAs poll (their completion waits use the deadline
    /// fallback) — see `probe`.
    irq_vector: u8,
}

impl core::fmt::Debug for Ahci {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ahci")
            .field("cap", &format_args!("{:#x}", self.cap))
            .field("vs", &format_args!("{:#x}", self.vs))
            .field("pi", &format_args!("{:#x}", self.pi))
            .field("ports", &self.ports.len())
            .finish_non_exhaustive()
    }
}

/// Register access for the HBA-global init sequence, so the same code
/// drives the real ABAR and the register model in the kernel tests.
pub trait AhciRegs {
    /// Read the 32-bit HBA register at byte offset `off`.
    fn read32(&self, off: u64) -> u32;
    /// Write the 32-bit HBA register at byte offset `off`.
    fn write32(&self, off: u64, val: u32);
}

/// The mapped ABAR. Only `Ahci::bring_up` (an `unsafe fn` whose caller
/// owns BAR5) constructs one.
struct Abar<'a>(&'a MmioRegion);

impl AhciRegs for Abar<'_> {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: `Abar` wraps the BAR5 mapping `Ahci::bring_up` owns;
        // every offset used by the init sequence is inside the HBA's
        // register block.
        unsafe { self.0.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: as in `read32`.
        unsafe { self.0.write32(off, val) }
    }
}

/// Outcome of the BIOS/OS handoff (AHCI 1.3.1 §10.6.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BiosHandoff {
    /// CAP2.BOH clear (or AHCI < 1.2): no handoff mechanism.
    NotSupported,
    /// OOS set and the BIOS released BOS within the wait.
    Completed,
    /// The BIOS kept BOS set past the 25 ms + 2 s waits; the OS
    /// proceeds anyway, as the spec allows.
    TimedOut,
}

/// HBA-global configuration captured by [`hba_global_init`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HbaConfig {
    pub cap: u32,
    pub cap2: u32,
    pub vs: u32,
    /// Implemented-port map after Linux's cross-check / fabrication.
    pub port_map: u32,
    /// Platform PxCMD capability bits per port, restored after reset.
    pub saved_port_cmd: [u32; 32],
    pub handoff: BiosHandoff,
}

/// Sleep `ms` while keeping the console pumps alive.
fn ahci_msleep(ms: u64) {
    narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(ms));
}

/// Linux `ahci_enable_ahci`: set GHC.AE, retrying up to five times
/// 10 ms apart ("Some controllers need AHCI_EN to be written multiple
/// times").
fn enable_ahci(regs: &impl AhciRegs) -> bool {
    let mut ghc = regs.read32(HBA_GHC);
    if ghc & GHC_AE != 0 {
        return true;
    }
    for _ in 0..5 {
        ghc |= GHC_AE;
        regs.write32(HBA_GHC, ghc);
        ghc = regs.read32(HBA_GHC);
        if ghc & GHC_AE != 0 {
            return true;
        }
        ahci_msleep(10);
    }
    false
}

/// Number of ports CAP.NP advertises (Linux `ahci_nr_ports`).
pub fn ahci_nr_ports(cap: u32) -> u32 {
    (cap & CAP_NP_MASK) + 1
}

/// Linux `ahci_save_initial_config` port-map rules: a PI with more ports
/// than CAP.NP is discarded, and below AHCI 1.3 an empty PI is
/// fabricated from CAP.NP.
pub fn effective_port_map(cap: u32, vs: u32, pi: u32) -> u32 {
    let nr = ahci_nr_ports(cap);
    let mut map = pi;
    if map != 0 && map.count_ones() > nr {
        map = 0;
    }
    if map == 0 && vs < 0x0001_0300 {
        map = if nr >= 32 { u32::MAX } else { (1u32 << nr) - 1 };
    }
    map
}

/// BIOS/OS handoff, AHCI 1.3.1 §10.6.3: set BOHC.OOS, wait up to 25 ms
/// for the BIOS to clear BOS, and if it has not (or reports BB) give it
/// 2 s to finish outstanding commands. Linux performs no handoff; NARF
/// follows the spec because a firmware that still owns the HBA could
/// otherwise race the reset below. The waits are bounded and the OS
/// proceeds either way.
fn bios_handoff(regs: &impl AhciRegs, cap2: u32) -> BiosHandoff {
    if cap2 & CAP2_BOH == 0 {
        return BiosHandoff::NotSupported;
    }
    let bohc = regs.read32(HBA_BOHC);
    if bohc & BOHC_BOS == 0 && bohc & BOHC_OOS != 0 {
        return BiosHandoff::Completed;
    }
    regs.write32(HBA_BOHC, bohc | BOHC_OOS);
    let released = narf_scheduler::responsive_spin_until(
        || regs.read32(HBA_BOHC) & BOHC_BOS == 0,
        narf_time::Deadline::after_ms(25),
    );
    if released && regs.read32(HBA_BOHC) & BOHC_BB == 0 {
        return BiosHandoff::Completed;
    }
    let released = narf_scheduler::responsive_spin_until(
        || regs.read32(HBA_BOHC) & (BOHC_BOS | BOHC_BB) == 0,
        narf_time::Deadline::after_ms(2_000),
    );
    if released {
        BiosHandoff::Completed
    } else {
        BiosHandoff::TimedOut
    }
}

/// HBA-global bring-up, mirroring Linux `ahci_save_initial_config` +
/// `ahci_reset_controller` (drivers/ata/libahci.c):
///
/// 1. Enable AHCI mode, take ownership from the BIOS.
/// 2. Save CAP / CAP2 / PI and each port's platform PxCMD bits. CAP and
///    PI are write-once registers firmware programs; some controllers
///    reset them on GHC.HR, so Linux writes them back afterwards.
/// 3. GHC.HR (unless already set), wait up to 1 s for it to self-clear
///    ("Reset must complete within 1 second, or the hardware should be
///    considered fried").
/// 4. Re-enable AHCI mode and restore the saved values.
pub fn hba_global_init(regs: &impl AhciRegs) -> Result<HbaConfig, AhciError> {
    if !enable_ahci(regs) {
        return Err(AhciError::AhciEnableFailed);
    }
    let vs = regs.read32(HBA_VS);
    let cap2 = if vs >= 0x0001_0200 {
        regs.read32(HBA_CAP2)
    } else {
        0
    };
    let handoff = bios_handoff(regs, cap2);
    let cap = regs.read32(HBA_CAP);
    let raw_pi = regs.read32(HBA_PI);
    let port_map = effective_port_map(cap, vs, raw_pi);
    // Linux writes the fabricated map back; a map it discarded for
    // disagreeing with CAP.NP keeps the original PI value.
    let saved_pi = if raw_pi == 0 { port_map } else { raw_pi };
    let mut saved_port_cmd = [0u32; 32];
    for (n, slot) in saved_port_cmd.iter_mut().enumerate() {
        if port_map & (1 << n) != 0 {
            let off = PORT_BASE_OFF + n as u64 * PORT_STRIDE;
            *slot = regs.read32(off + PORT_CMD) & CMD_CAP_MASK;
        }
    }

    // Global reset.
    if !enable_ahci(regs) {
        return Err(AhciError::AhciEnableFailed);
    }
    let ghc = regs.read32(HBA_GHC);
    if ghc & GHC_HR == 0 {
        regs.write32(HBA_GHC, ghc | GHC_HR);
        let _ = regs.read32(HBA_GHC); // flush
    }
    let done = narf_scheduler::responsive_spin_until(
        || regs.read32(HBA_GHC) & GHC_HR == 0,
        narf_time::Deadline::after_ms(1_000),
    );
    if !done {
        return Err(AhciError::ResetTimeout);
    }
    if !enable_ahci(regs) {
        return Err(AhciError::AhciEnableFailed);
    }
    // ahci_restore_initial_config.
    regs.write32(HBA_CAP, cap);
    if cap2 != 0 {
        regs.write32(HBA_CAP2, cap2);
    }
    regs.write32(HBA_PI, saved_pi);
    let _ = regs.read32(HBA_PI); // flush
    for (n, &bits) in saved_port_cmd.iter().enumerate() {
        if port_map & (1 << n) != 0 {
            let off = PORT_BASE_OFF + n as u64 * PORT_STRIDE;
            regs.write32(off + PORT_CMD, bits);
        }
    }
    Ok(HbaConfig {
        cap,
        cap2,
        vs,
        port_map,
        saved_port_cmd,
        handoff,
    })
}

/// SATA link debounce timing `{ interval, duration, timeout }` in ms
/// (Linux `sata_deb_timing_normal`).
pub const SATA_DEB_TIMING_NORMAL: [u64; 3] = [5, 100, 2_000];

/// Linux `sata_link_debounce`: sample PxSSTS.DET every `interval` ms
/// until it holds one value for `duration` ms (DET = 1, "device present,
/// no PHY communication", keeps waiting until the deadline). Returns the
/// settled DET, or `None` if DET was still changing at the deadline.
pub fn sata_link_debounce(read_det: impl FnMut() -> u32, timing: [u64; 3]) -> Option<u32> {
    sata_link_debounce_within(read_det, timing, None)
}

/// [`sata_link_debounce`] whose deadline is also clamped to `budget`.
fn sata_link_debounce_within(
    mut read_det: impl FnMut() -> u32,
    timing: [u64; 3],
    budget: Option<narf_time::Deadline>,
) -> Option<u32> {
    let [interval, duration, timeout] = timing;
    let deadline = clamp_deadline(timeout, budget);
    let mut last = read_det() & 0xF;
    let mut stable = narf_time::Deadline::after_ms(duration);
    loop {
        ahci_msleep(interval);
        let cur = read_det() & 0xF;
        if cur == last {
            if cur == 1 && !deadline.expired() {
                continue;
            }
            if stable.expired() {
                return Some(cur);
            }
            continue;
        }
        last = cur;
        stable = narf_time::Deadline::after_ms(duration);
        if deadline.expired() {
            return None;
        }
    }
}

/// Wall-clock cap on bringing up *all* ports of one HBA. Linux resets the
/// ports of a host in parallel (one libata EH thread per port, each with its
/// own `ata_eh_reset_timeouts` budget — 10 s for the first BSY wait), so the
/// whole host costs about one port's worst case. NARF resets ports one after
/// another; without this cap every absent-but-DET=3 or never-ready port cost
/// up to ~15 s (engine stop 1.5 s, COMRESET tries 1 s, debounce 2 s, BSY
/// 10 s) serially. Ports reached after the budget is spent are classified
/// from their registers without a reset (still stopped first, which is what
/// makes reprogramming them safe).
pub const HBA_PORT_BRINGUP_BUDGET_MS: u64 = 15_000;

/// `after_ms(ms)`, or `budget` when that is earlier.
fn clamp_deadline(ms: u64, budget: Option<narf_time::Deadline>) -> narf_time::Deadline {
    let own = narf_time::Deadline::after_ms(ms);
    match budget {
        Some(b) if b < own => b,
        _ => own,
    }
}

const fn port_off(port_index: u8) -> u64 {
    PORT_BASE_OFF + (port_index as u64) * PORT_STRIDE
}

/// Linux `ahci_stop_engine` + `ahci_stop_fis_rx`: clear PxCMD.ST and
/// wait (500 ms) for CR, then clear FRE and wait (1 s) for FR.
pub fn port_deinit(regs: &impl AhciRegs, port_index: u8) -> Result<(), AhciError> {
    let off = port_off(port_index);
    let cmd = regs.read32(off + PORT_CMD);
    if cmd == 0xFFFF_FFFF {
        // Controller gone (Linux: "AHCI controller unavailable!").
        return Err(AhciError::PortIdleTimeout);
    }
    if cmd & (CMD_ST | CMD_CR) != 0 {
        regs.write32(off + PORT_CMD, cmd & !CMD_ST);
        let ok = narf_scheduler::responsive_spin_until(
            || regs.read32(off + PORT_CMD) & CMD_CR == 0,
            narf_time::Deadline::after_ms(500),
        );
        if !ok {
            return Err(AhciError::PortIdleTimeout);
        }
    }
    let cmd = regs.read32(off + PORT_CMD);
    if cmd & (CMD_FRE | CMD_FR) != 0 {
        regs.write32(off + PORT_CMD, cmd & !CMD_FRE);
        let ok = narf_scheduler::responsive_spin_until(
            || regs.read32(off + PORT_CMD) & CMD_FR == 0,
            narf_time::Deadline::after_ms(1_000),
        );
        if !ok {
            return Err(AhciError::PortIdleTimeout);
        }
    }
    Ok(())
}

/// Clear SERR (W1C), PxIS (W1C) and this port's HBA IS bit — Linux
/// `ahci_port_clear_pending_irq`.
fn port_clear_pending(regs: &impl AhciRegs, port_index: u8) {
    let off = port_off(port_index);
    let serr = regs.read32(off + PORT_SERR);
    regs.write32(off + PORT_SERR, serr);
    let is = regs.read32(off + PORT_IS);
    if is != 0 {
        regs.write32(off + PORT_IS, is);
    }
    regs.write32(HBA_IS, 1u32 << port_index);
}

/// Classify a port from its current registers, without resetting the link
/// (no FIS area could be allocated, or the HBA's bring-up budget is spent).
fn port_classify_passive(regs: &impl AhciRegs, port_index: u8) -> PortKind {
    let off = port_off(port_index);
    let _ = port_deinit(regs, port_index);
    port_clear_pending(regs, port_index);
    PortKind::from_sig(regs.read32(off + PORT_SIG), regs.read32(off + PORT_SSTS))
}

/// Linux `sata_link_hardreset` + `sata_link_resume`: COMRESET via
/// PxSCTL.DET = 1 for ≥ 1 ms (keeping SPD, IPM = 3), release with up to
/// five tries, wait 200 ms, debounce, clear SERR. Returns whether the link
/// is online (DET = 3). Every wait is clamped to `budget`. The engine
/// (PxCMD.ST) must be stopped.
fn link_hardreset(regs: &impl AhciRegs, port_index: u8, budget: narf_time::Deadline) -> bool {
    let off = port_off(port_index);
    let sctl = regs.read32(off + PORT_SCTL);
    regs.write32(off + PORT_SCTL, (sctl & 0x0F0) | 0x301);
    let _ = regs.read32(off + PORT_SCTL); // flush
                                          // AHCI 1.1 §10.4.2: hold COMRESET at least 1 ms.
    ahci_msleep(1);
    let mut tries = 5;
    loop {
        let sctl = regs.read32(off + PORT_SCTL);
        regs.write32(off + PORT_SCTL, (sctl & 0x0F0) | 0x300);
        // "Some PHYs react badly if SStatus is pounded immediately
        // after resuming. Delay 200ms before debouncing."
        ahci_msleep(200);
        let sctl = regs.read32(off + PORT_SCTL);
        tries -= 1;
        if sctl & 0xF0F == 0x300 || tries == 0 || budget.expired() {
            break;
        }
    }
    let det = sata_link_debounce_within(
        || regs.read32(off + PORT_SSTS),
        SATA_DEB_TIMING_NORMAL,
        Some(budget),
    );
    let serr = regs.read32(off + PORT_SERR);
    regs.write32(off + PORT_SERR, serr);
    det == Some(SSTS_DET_PRESENT)
}

/// Port init + link hardreset + classification (see `Ahci::bring_up`),
/// with every link wait clamped to the HBA's `budget`. `clb` / `fb` are the
/// bus addresses of the shared init command list and this port's FIS area;
/// the caller has seeded the FIS area's D2H status with BSY. Leaves the
/// port with ST and FRE clear, the state every command path expects before
/// it reprograms CLB / FB. A port whose engine will not stop is left alone
/// (never pointed at the init area) and reported as `None`.
pub fn port_init_and_classify(
    regs: &impl AhciRegs,
    cap: u32,
    port_index: u8,
    clb: u64,
    fb: u64,
    budget: narf_time::Deadline,
) -> PortKind {
    let off = port_off(port_index);
    // ahci_port_init: make sure the port is not active.
    if port_deinit(regs, port_index).is_err() {
        return PortKind::None;
    }
    port_clear_pending(regs, port_index);

    // ahci_start_fis_rx: CLB / FB (upper dwords only with S64A), then FRE.
    compiler_fence(Ordering::SeqCst);
    if cap & CAP_S64A != 0 {
        regs.write32(off + 0x04, (clb >> 32) as u32);
        regs.write32(off + 0x0C, (fb >> 32) as u32);
    }
    regs.write32(off, clb as u32);
    regs.write32(off + 0x08, fb as u32);
    let cmd = regs.read32(off + PORT_CMD);
    regs.write32(off + PORT_CMD, cmd | CMD_FRE);
    let _ = regs.read32(off + PORT_CMD);

    // ahci_power_up: spin up (only meaningful with CAP.SSS) and set the
    // interface active.
    let mut cmd = regs.read32(off + PORT_CMD) & !CMD_ICC_MASK;
    if cap & CAP_SSS != 0 {
        cmd |= CMD_SUD;
        regs.write32(off + PORT_CMD, cmd);
    }
    regs.write32(off + PORT_CMD, cmd | CMD_ICC_ACTIVE);

    let kind = if link_hardreset(regs, port_index, budget) {
        // ata_wait_ready with ahci_check_ready: BSY clear = ready,
        // 0xFF = no device.
        let mut absent = false;
        let ready = narf_scheduler::responsive_spin_until(
            || {
                let st = regs.read32(off + PORT_TFD) & 0xFF;
                if st == 0xFF {
                    absent = true;
                    return true;
                }
                st & ATA_BUSY == 0
            },
            clamp_deadline(10_000, Some(budget)),
        );
        if absent || !ready {
            PortKind::None
        } else {
            PortKind::from_sig(regs.read32(off + PORT_SIG), regs.read32(off + PORT_SSTS))
        }
    } else {
        PortKind::None
    };

    // Back to the idle baseline the command paths expect.
    let _ = port_deinit(regs, port_index);
    port_clear_pending(regs, port_index);
    kind
}

/// Bring up every implemented port of `port_map` under one HBA-wide
/// deadline ([`HBA_PORT_BRINGUP_BUDGET_MS`] from the call): a port reached
/// with budget left is reset and classified by [`port_init_and_classify`],
/// later ones only passively. `init` is `(clb, fis_base)`, the init area's
/// command list and FIS-area base (port `n` at `fis_base + n * 0x100`), or
/// `None` to classify every port passively. Each port's stale PxIS is
/// cleared and PxIE set to the events the driver handles; nothing reaches
/// the CPU until [`hba_enable_irq`].
pub fn bring_up_ports(
    regs: &impl AhciRegs,
    cap: u32,
    port_map: u32,
    init: Option<(u64, u64)>,
    budget_ms: u64,
) -> alloc::vec::Vec<PortInfo> {
    let budget = narf_time::Deadline::after_ms(budget_ms);
    let mut ports = alloc::vec::Vec::new();
    for n in 0..32u8 {
        if port_map & (1u32 << n) == 0 {
            continue;
        }
        let kind = match init {
            Some((clb, fis_base)) if !budget.expired() => {
                port_init_and_classify(regs, cap, n, clb, fis_base + n as u64 * 0x100, budget)
            }
            _ => port_classify_passive(regs, n),
        };
        let off = port_off(n);
        // Clear stale PORT_IS (W1C, §3.3.5) and unmask the events we care
        // about (§3.3.6).
        regs.write32(off + PORT_IS, 0xFFFF_FFFF);
        regs.write32(off + PORT_IE, PORT_IE_MASK);
        ports.push(PortInfo { index: n, kind });
    }
    ports
}

/// End of the HBA init: clear the HBA IS bits the port bring-up latched and
/// keep GHC.AE set. GHC.IE stays clear — the platform has not routed a
/// vector yet, and an HBA allowed to assert a (possibly shared, level) INTx
/// line with no handler behind it would storm. [`hba_enable_irq`] sets it.
pub fn hba_finish_init(regs: &impl AhciRegs) {
    let is = regs.read32(HBA_IS);
    regs.write32(HBA_IS, is);
    let ghc = regs.read32(HBA_GHC);
    regs.write32(HBA_GHC, (ghc | GHC_AE) & !GHC_IE);
}

/// Set GHC.IE (AHCI 1.3.1 §3.1.2), the HBA's master interrupt gate. Call
/// only once an ISR is installed and the vector routed; the Linux order is
/// `ahci_init_controller` (PxIE still 0) then `ahci_host_activate`
/// (`request_irq`) before any port is thawed.
pub fn hba_enable_irq(regs: &impl AhciRegs) {
    let ghc = regs.read32(HBA_GHC);
    regs.write32(HBA_GHC, ghc | GHC_AE | GHC_IE);
}

/// Stop a port's command engine and FIS receive — clear PORT_CMD.ST and
/// FRE and wait (500 ms) for CR and FR to clear. Required before CLB / FB
/// are reprogrammed or the memory they point at is released.
pub fn port_idle(regs: &impl AhciRegs, port_index: u8) -> Result<(), AhciError> {
    let off = port_off(port_index);
    let cmd = regs.read32(off + PORT_CMD);
    regs.write32(off + PORT_CMD, cmd & !(CMD_ST | CMD_FRE));
    // AHCI 1.3.1 §10.3.2: post-clear-ST the engine drains within 500 ms;
    // FR drain after clear-FRE is similar.
    let done = narf_scheduler::responsive_spin_until(
        || regs.read32(off + PORT_CMD) & (CMD_FR | CMD_CR) == 0,
        narf_time::Deadline::after_ms(500),
    );
    if done {
        Ok(())
    } else {
        Err(AhciError::PortIdleTimeout)
    }
}

/// Byte offset of port `n`'s FIS receive area inside the init DMA
/// buffer (256-byte aligned, AHCI §3.3.3); the shared command list sits
/// at offset 0 (1 KiB aligned).
const INIT_FIS_BASE: u64 = 0x400;
/// Init DMA size: 1 KiB command list + 32 × 256-byte FIS areas.
const INIT_DMA_BYTES: usize = 0x400 + 32 * 0x100;

impl Ahci {
    /// Bring up the HBA and every implemented port.
    ///
    /// HBA level: [`hba_global_init`] (AHCI enable, BIOS/OS handoff,
    /// Linux's save / reset / restore of CAP, PI and the port
    /// capability bits). Port level, mirroring `ahci_port_init` and the
    /// libata probe hardreset (`ahci_do_hardreset` →
    /// `sata_link_hardreset`): stop the engines, clear SERR/IS, point
    /// the port at a FIS receive area, enable FIS reception, spin the
    /// device up, COMRESET, debounce the link and wait (10 s, Linux's
    /// first `ata_eh_reset_timeouts` step) for BSY to clear before the
    /// signature is classified. Every wait is bounded; no media is
    /// touched.
    ///
    /// # Safety
    /// Caller owns the device's BAR5 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AhciError> {
        // SAFETY: caller-authority.
        let mmio = unsafe { map_bar(device, ABAR_BAR) }.map_err(|_| AhciError::BarMapFailed)?;
        let cfg = hba_global_init(&Abar(&mmio))?;
        let cap = cfg.cap;

        // FIS receive areas for the link bring-up. Without CAP.S64A the
        // HBA only sees the low address dword, so the area must sit
        // below 4 GiB; skip the per-port bring-up rather than point the
        // device at the wrong memory.
        let init_dma = alloc_coherent(INIT_DMA_BYTES, DomainId::DRIVER_0)
            .ok()
            .filter(|b| {
                cap & CAP_S64A != 0 || b.dma_addr().raw() + INIT_DMA_BYTES as u64 <= 1u64 << 32
            });

        // Drain stale HBA-level interrupt state (W1C, §3.1.3).
        // SAFETY: identity-mapped MMIO.
        let stale_is = unsafe { mmio.read32(HBA_IS) };
        // SAFETY: same.
        unsafe {
            mmio.write32(HBA_IS, stale_is);
        }

        let mut dev = Self {
            mmio,
            addr: device.addr,
            cap,
            cap2: cfg.cap2,
            vs: cfg.vs,
            pi: cfg.port_map,
            ports: alloc::vec::Vec::new(),
            handoff: cfg.handoff,
            block_port: 0,
            capacity: 0,
            _init_dma: None,
            req_gate: AtomicBool::new(false),
            scratch: IrqSafeSpinLock::new(None),
            xfer: IrqSafeSpinLock::new(None),
            disks: IrqSafeSpinLock::new(alloc::vec::Vec::new()),
            suspended: AtomicBool::new(false),
            irq_vector: 0,
        };

        // Seed every FIS area's D2H Register FIS status (RFIS + 0x40 + 2)
        // with BSY, like `ahci_do_hardreset`, so a stale FIS can never read
        // as "ready".
        if let Some(buf) = init_dma.as_ref() {
            for n in 0..32u64 {
                // SAFETY: coherent DMA buffer of INIT_DMA_BYTES; the FIS
                // area offset + 0x42 is in bounds for every port.
                unsafe {
                    core::ptr::write_volatile(
                        buf.cpu_mut_ptr_at::<u8>(INIT_FIS_BASE + n * 0x100 + 0x42),
                        ATA_BUSY as u8,
                    );
                }
            }
        }
        let init = init_dma
            .as_ref()
            .map(|b| (b.dma_addr().raw(), b.dma_addr_at(INIT_FIS_BASE).raw()));
        dev.ports = bring_up_ports(
            &Abar(&dev.mmio),
            cap,
            cfg.port_map,
            init,
            HBA_PORT_BRINGUP_BUDGET_MS,
        );
        dev._init_dma = init_dma;
        dev.block_port = dev
            .ports
            .iter()
            .find(|p| p.kind == PortKind::Sata)
            .map(|p| p.index)
            .unwrap_or(0);

        // Clear the HBA IS bits the port bring-up latched. GHC.IE is set
        // by `probe` only once the platform has routed a vector.
        hba_finish_init(&Abar(&dev.mmio));
        Ok(dev)
    }

    /// Write the PORT_CI doorbell for the slot mask `bit` and wait
    /// for completion via the IRQ path. The wait future is
    /// constructed BEFORE the doorbell write — an IRQ landing
    /// between doorbell and waiter-construction would let the
    /// baseline fire-count capture a post-IRQ value and hang the
    /// await forever (see `interrupts/src/wait.rs` and the matching
    /// fix in `drivers/nvme/src/lib.rs::submit_io_irq_async`).
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively;
    /// `port_idx < 32`; PORT_CLB / PORT_FB / PORT_CMD are programmed
    /// and `bit` corresponds to the slot whose command-table is set
    /// up.
    pub async unsafe fn issue_and_wait_async(
        &self,
        port_idx: u8,
        bit: u32,
    ) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
        // Per-controller vector (#931): only the first installed HBA
        // owns the shared ISR; a later HBA must not await an IRQ
        // that can only ever describe the first controller's ports.
        let vector = self.irq_vector;

        if vector == 0 {
            // No IRQ wired — issue + sync-poll.
            compiler_fence(Ordering::SeqCst);
            // SAFETY: identity-mapped MMIO.
            unsafe {
                self.mmio.write32(off + PORT_CI, bit);
            }
            // SAFETY: caller-asserted ownership.
            return unsafe { self.issue_and_wait_sync(port_idx, bit) };
        }

        // Construct the waiter FIRST — captures the pre-doorbell
        // fire_count baseline. Then ring CI. Then await.
        // Each wait is bounded by a 5 s deadline — matches Linux
        // libata's ATA_TMOUT_INTERNAL_QUICK. On expiry we fall
        // through the loop to re-read CI: if the command actually
        // completed but the IRQ was lost, the read sees ci & bit
        // == 0 and returns Ok. Otherwise loop again with a fresh
        // baseline (bounded by the total command-level timeout
        // the caller enforces).
        let mut deadline = narf_time::Deadline::after_ms(5_000);
        let mut waiter = narf_interrupts::wait_for_irq_until(vector, deadline);
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(off + PORT_CI, bit);
        }

        loop {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { self.mmio.read32(off + PORT_CI) };
            // SAFETY: same.
            let tfd = unsafe { self.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                return Err(AhciError::ResetTimeout);
            }
            if ci & bit == 0 {
                return Ok(());
            }
            // Park until the next IRQ OR deadline. After wake-up,
            // install a fresh waiter for the next iteration so we
            // observe any IRQ that lands between this drain and
            // the next CI read.
            let _ = (&mut waiter).await;
            deadline = narf_time::Deadline::after_ms(5_000);
            waiter = narf_interrupts::wait_for_irq_until(vector, deadline);
        }
    }

    /// Sync polled completion — kept for the existing block-device
    /// path so smoke tests that call directly into `ahci_read_lba`
    /// don't change behaviour.
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively;
    /// `port_idx < 32`; the slots in `bit` have already been issued.
    pub unsafe fn issue_and_wait_sync(&self, port_idx: u8, bit: u32) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
        // responsive_spin_until keeps cursor/FB alive while waiting
        // for the controller to clear CI; bail early on TFD.ERR.
        // 30 s wall-clock budget covers the worst-case ATA DMA
        // timeout for spinning rust (per ATA-8 §4.20.1 the longest
        // legitimate command is bounded well below this).
        let mut errored = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: identity-mapped MMIO.
                let ci = unsafe { self.mmio.read32(off + PORT_CI) };
                // SAFETY: same.
                let tfd = unsafe { self.mmio.read32(off + 0x20) };
                if tfd & 0x01 != 0 {
                    errored = true;
                    return true;
                }
                ci & bit == 0
            },
            narf_time::Deadline::after_ms(30_000),
        );
        if errored || !done {
            return Err(AhciError::ResetTimeout);
        }
        Ok(())
    }

    /// Stop a port — clears PORT_CMD.ST + PORT_CMD.FRE and waits for
    /// CR + FR to clear. Required before reprogramming CLB / FB.
    ///
    /// # Safety
    /// Caller owns the HBA exclusively; `port_index < 32`.
    pub unsafe fn port_idle(&self, port_index: u8) -> Result<(), AhciError> {
        port_idle(&Abar(&self.mmio), port_index)
    }

    /// COMRESET / SATA link-up sequence for a port.
    ///
    /// Sequence (mirrors `libata::sata_link_hardreset`, Linux
    /// `drivers/ata/libata-sata.c::sata_link_hardreset`):
    ///
    /// 1. Idle the port (CMD.ST = 0, wait CR = 0) via `port_idle`.
    /// 2. Set PORT_SCTL.DET = 1 — asserts COMRESET on the SATA PHY.
    /// 3. Hold for ≥ 1 ms (AHCI 1.3.1 §10.4.2 / SATA I spec §7.2.2).
    /// 4. Clear PORT_SCTL.DET = 0 — release COMRESET, begin OOB.
    /// 5. Poll PORT_SSTS.DET until it reads 3 (device + comms OK);
    ///    bail after 1 s.
    ///
    /// On success the port is ready for CLB/FB programming + FRE/ST.
    ///
    /// # Safety
    /// Caller owns the HBA exclusively; `port_index < 32`.
    pub unsafe fn port_reset(&self, port_index: u8) -> Result<(), AhciError> {
        let off = PORT_BASE_OFF + (port_index as u64) * PORT_STRIDE;

        // 1. Stop any running command engine.
        // SAFETY: delegated; same ownership contract.
        unsafe { self.port_idle(port_index) }?;

        // 2. Write PORT_SCTL.DET = 1 (COMRESET), preserving other
        //    SPD / IPM fields. Linux uses mask 0x0f0 to keep the
        //    SPD nibble: `(scontrol & 0x0f0) | 0x301`.
        // SAFETY: identity-mapped MMIO.
        let sctl = unsafe { self.mmio.read32(off + PORT_SCTL) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SCTL, (sctl & 0x0F0) | 0x301);
        }

        // 3. Hold COMRESET for ≥ 1 ms (spec minimum).
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(1));

        // 4. Release COMRESET: DET = 0, keep SPD/IPM as-is.
        // SAFETY: identity-mapped MMIO.
        let sctl = unsafe { self.mmio.read32(off + PORT_SCTL) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SCTL, sctl & !0x0F);
        }

        // 5. Wait for PORT_SSTS.DET = 3 (device present + comms OK).
        //    AHCI 1.3.1 §10.1.2 allows up to 1 s for COMRESET to
        //    complete and OOB to finish.
        let found = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read32(off + PORT_SSTS) } & 0x0F == SSTS_DET_PRESENT,
            narf_time::Deadline::after_ms(1_000),
        );
        if !found {
            return Err(AhciError::ResetTimeout);
        }

        // Clear any SERR / PORT_IS latched during OOB.
        // SAFETY: identity-mapped MMIO.
        let serr = unsafe { self.mmio.read32(off + PORT_SERR) };
        // SAFETY: same.
        unsafe {
            self.mmio.write32(off + PORT_SERR, serr);
            self.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        }

        Ok(())
    }

    /// HBA's capability bitmap.
    pub fn caps(&self) -> u32 {
        self.cap
    }

    /// AHCI version (BCD, e.g. 0x0001_0301 = v1.3.1).
    pub fn version(&self) -> u32 {
        self.vs
    }

    /// Implemented-port bitmap (PI register).
    pub fn ports_implemented(&self) -> u32 {
        self.pi
    }

    /// Issue ATA `IDENTIFY DEVICE` (opcode 0xEC) on the given port,
    /// returning the 512-byte device-data block.
    ///
    /// Stage-4 cut: allocates per-call DMA structures (command list +
    /// FIS receive + command table + 512-byte data buffer) and frees
    /// them after the response arrives. A real driver caches these
    /// per port; we trade allocations for code simplicity until the
    /// per-port BlockDevice surface lands.
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively; `port_idx <
    /// 32` and the port's PortKind was Sata at probe.
    pub unsafe fn identify_device(&self, port_idx: u8) -> Result<[u8; 512], AhciError> {
        // SAFETY: forwarded caller contract.
        unsafe { identify_device(&Abar(&self.mmio), self.cap, port_idx) }
    }

    /// Physical address of this controller's persistent 4 KiB
    /// command scratch, allocating it on first use.
    fn scratch_phys(&self) -> u64 {
        persistent_dma_phys(&self.scratch, self.cap, 4096)
    }

    /// Physical address of this controller's persistent
    /// bulk-transfer buffer ([`AHCI_XFER_BYTES`]), allocating it on
    /// first use. The block path's PRDT points here for transfers
    /// larger than the scratch page's data area (#930).
    fn xfer_phys(&self) -> u64 {
        persistent_dma_phys(&self.xfer, self.cap, AHCI_XFER_BYTES)
    }

    /// Snapshot of the disks published for this controller (#931).
    pub fn disks(&self) -> alloc::vec::Vec<DiskInfo> {
        self.disks.lock().clone()
    }

    /// The published disk behind `port`, if that port carries one.
    pub fn disk_on_port(&self, port: u8) -> Option<DiskInfo> {
        self.disks.lock().iter().find(|d| d.port == port).cloned()
    }

    /// Replace the published-disk table (probe fills it before the
    /// controller is installed; the resume path refreshes it after
    /// revalidation, #932).
    fn set_disks(&self, disks: alloc::vec::Vec<DiskInfo>) {
        *self.disks.lock() = disks;
    }

    /// True while the device_pm suspend handler has this controller
    /// quiesced (#932). The block surface refuses I/O in that state.
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::Acquire)
    }

    /// Issue FLUSH CACHE (EXT when `ext`) on a port of this
    /// controller (#841). See the free [`flush_cache`].
    ///
    /// # Safety
    /// Caller owns the HBA + the named port exclusively (the block
    /// surface holds the request gate); `port_idx < 32`.
    pub unsafe fn flush_cache(&self, port_idx: u8, ext: bool) -> Result<(), AhciError> {
        // SAFETY: forwarded caller contract.
        unsafe { flush_cache(&Abar(&self.mmio), self.cap, port_idx, ext) }
    }

    /// Issue DATA SET MANAGEMENT/TRIM for `ranges` on a port of
    /// this controller (#841). See the free [`dsm_trim`].
    ///
    /// # Safety
    /// Same contract as [`Self::flush_cache`].
    pub unsafe fn dsm_trim(
        &self,
        port_idx: u8,
        ranges: &[(u64, u16)],
        max_blocks: u16,
    ) -> Result<(), AhciError> {
        // SAFETY: forwarded caller contract.
        unsafe { dsm_trim(&Abar(&self.mmio), self.cap, port_idx, ranges, max_blocks) }
    }
}

/// [`Ahci::identify_device`] over any register block.
///
/// The port must be stopped before CLB / FB are pointed at the scratch
/// page: a failed [`port_idle`] is returned as is (Linux `ahci_stop_engine`
/// failing makes `ahci_port_start`/EH give up on the port rather than
/// reprogram a running engine). Once the page has been handed to the HBA it
/// is released only after a final [`port_idle`] confirms CR = FR = 0;
/// otherwise it is leaked (`mem::forget`), since a live FIS-receive engine
/// may still write it.
///
/// # Safety
/// `regs` is the HBA the caller owns exclusively; `port_idx < 32`.
pub unsafe fn identify_device(
    regs: &impl AhciRegs,
    cap: u32,
    port_idx: u8,
) -> Result<[u8; 512], AhciError> {
    let off = port_off(port_idx);

    // Stop the port; never reprogram CLB / FB under a running engine.
    port_idle(regs, port_idx)?;

    // Allocate one 4 KiB DMA page covering everything:
    //   +0x000  Command List  (1 KiB, 32 entries × 32 bytes)
    //   +0x400  Received FIS  (256 bytes)
    //   +0x500  Command Table (128 bytes — 64 cfis + 0 acmd + 16 PRDT0)
    //   +0x600  Data buffer   (512 bytes for IDENTIFY response)
    let scratch = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| AhciError::BarMapFailed)?;
    // Without CAP.S64A the HBA sees only the low address dword.
    if cap & CAP_S64A == 0 && scratch.dma_addr().raw() + 4096 > 1u64 << 32 {
        return Err(AhciError::BarMapFailed);
    }
    // Device-side handles (programmed into the HBA) and CPU-side
    // pointers (dereferenced here) are now separate types, so the two
    // cannot be confused: `DmaAddr` has no pointer conversion at all.
    const OFF_CMD_LIST: u64 = 0x000;
    const OFF_FIS_RECV: u64 = 0x400;
    const OFF_CMD_TBL: u64 = 0x500;
    const OFF_DATA_BUF: u64 = 0x600;
    const OFF_PRDT: u64 = OFF_CMD_TBL + 0x80;

    let cmd_list_dma = scratch.dma_addr_at(OFF_CMD_LIST);
    let fis_recv_dma = scratch.dma_addr_at(OFF_FIS_RECV);
    let cmd_tbl_dma = scratch.dma_addr_at(OFF_CMD_TBL);
    let data_buf_dma = scratch.dma_addr_at(OFF_DATA_BUF);

    // Zero the regions we touch. Bulk `write_bytes`, not a
    // per-byte volatile loop — the scratch is coherent DMA memory,
    // not MMIO, and the ordering that matters is the fence before
    // the CI doorbell below, which publishes these stores before
    // the device can look.
    // SAFETY: coherent DMA page, reached through the kernel direct map.
    unsafe {
        core::ptr::write_bytes(scratch.cpu_mut_ptr::<u8>(), 0, 0x600 + 512);
    }

    // Command List entry 0: H[5..0] = FIS length in DWORDs (5
    // for H2D Register FIS), W bit = 0 (read), PRDT length = 1.
    // Fields:
    //   +0x00 u32 = (PRDT length << 16) | flags
    //   +0x04 u32 = bytes transferred (RW; HBA writes)
    //   +0x08 u64 = command-table phys
    //
    // CFL = 5 (H2D FIS = 5 DWORDs). Bits[4:0]. R=0, B=0, C=0,
    // RST=0, P=0. PRDT length = 1.
    // SAFETY: coherent DMA page, reached through the kernel direct map.
    unsafe {
        core::ptr::write_volatile(
            scratch.cpu_mut_ptr_at::<u32>(OFF_CMD_LIST),
            (1u32 << 16) | 5,
        );
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_CMD_LIST + 4), 0);
        // Value stays PHYSICAL — the HBA dereferences it.
        core::ptr::write_volatile(
            scratch.cpu_mut_ptr_at::<u64>(OFF_CMD_LIST + 8),
            cmd_tbl_dma.raw(),
        );
    }

    // Command Table:
    //   +0x00..0x40  CFIS (Command FIS — 64 bytes)
    //   +0x40..0x50  ACMD (ATAPI command — 16 bytes; unused)
    //   +0x50..0x80  Reserved
    //   +0x80..0x90  PRDT entry 0 (16 bytes)
    //
    // CFIS = H2D Register FIS (FIS type 0x27):
    //   +0  type = 0x27
    //   +1  bit 7 = C (command), bits[3:0] = port multiplier
    //   +2  command = 0xEC (IDENTIFY DEVICE)
    //   +3  features (low) = 0
    // SAFETY: same DMA page.
    unsafe {
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL), 0x27);
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 1), 0x80);
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 2), 0xEC);
    }
    // PRDT entry 0 at +0x80 of cmd table:
    //   +0x00 u64 data base PA
    //   +0x08 u32 reserved
    //   +0x0C u32 = (Interrupt-on-completion bit 31) | (byte count - 1)
    // SAFETY: same DMA page.
    unsafe {
        // PRDT data base stays PHYSICAL — the HBA DMAs to it.
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u64>(OFF_PRDT), data_buf_dma.raw());
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_PRDT + 8), 0);
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_PRDT + 12), 511);
    }

    // Program port CLB / FB (the port is stopped: `port_idle` above).
    regs.write32(off, cmd_list_dma.raw() as u32);
    regs.write32(off + 0x04, (cmd_list_dma.raw() >> 32) as u32);
    regs.write32(off + 0x08, fis_recv_dma.raw() as u32);
    regs.write32(off + 0x0C, (fis_recv_dma.raw() >> 32) as u32);

    // Clear PORT_IS / PORT_SERR (write-1-to-clear).
    let serr = regs.read32(off + PORT_SERR);
    regs.write32(off + PORT_SERR, serr);
    regs.write32(off + PORT_IS, 0xFFFF_FFFF);

    // Start the port (FRE first, then ST).
    let cmd = regs.read32(off + PORT_CMD);
    regs.write32(off + PORT_CMD, cmd | CMD_FRE);
    let cmd = regs.read32(off + PORT_CMD);
    regs.write32(off + PORT_CMD, cmd | CMD_ST);

    // Issue command 0 by writing PORT_CI bit 0.
    compiler_fence(Ordering::SeqCst);
    regs.write32(off + PORT_CI, 1);

    // Poll until CI bit clears. responsive_spin_until keeps cursor
    // / FB / serial alive and bails on TFD.ERR. IDENTIFY DEVICE
    // is sub-millisecond on real hardware; 5 s wall-clock budget
    // covers a stuck/slow controller without hanging boot.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let ci = regs.read32(off + PORT_CI);
            let tfd = regs.read32(off + PORT_TFD);
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(5_000),
    );
    if errored || !done {
        // The HBA may still own the command; never hand the page back
        // to the allocator while it can be a DMA target.
        core::mem::forget(scratch);
        return Err(AhciError::ResetTimeout);
    }

    // Copy out the IDENTIFY DEVICE response. The CI-clear poll
    // above is what makes the device's writes visible; fence so
    // the bulk copy cannot be hoisted above it.
    compiler_fence(Ordering::Acquire);
    let mut out = [0u8; 512];
    // SAFETY: `data_buf` is the base of the 512-byte DMA region the
    // HBA filled with the IDENTIFY response; `out` is a stack array
    // that cannot overlap the identity-mapped DMA page. Bulk copy
    // rather than a per-byte volatile loop — the payload is
    // coherent DMA memory, not MMIO.
    unsafe {
        core::ptr::copy_nonoverlapping(
            scratch.cpu_ptr::<u8>().add(OFF_DATA_BUF as usize),
            out.as_mut_ptr(),
            512,
        );
    }
    // Stop the port. Only a confirmed stop (FR = CR = 0) lets the
    // scratch page go back to the allocator.
    if let Err(e) = port_idle(regs, port_idx) {
        core::mem::forget(scratch);
        return Err(e);
    }
    Ok(out)
}

/// Encode one 512-byte DATA SET MANAGEMENT range block: up to 64
/// ranges, each 8 bytes — 48-bit LBA little-endian followed by a
/// 16-bit sector count little-endian (ACS, DATA SET MANAGEMENT
/// parameter layout). Unused entries are zero. Returns how many
/// of `ranges` were consumed. Pure — the byte-exact fixture for
/// the TRIM path (#841).
pub fn encode_dsm_range_block(ranges: &[(u64, u16)], out: &mut [u8; 512]) -> usize {
    *out = [0u8; 512];
    let n = ranges.len().min(64);
    for (i, &(lba, count)) in ranges.iter().take(n).enumerate() {
        let base = i * 8;
        out[base..base + 6].copy_from_slice(&lba.to_le_bytes()[..6]);
        out[base + 6..base + 8].copy_from_slice(&count.to_le_bytes());
    }
    n
}

/// Most 512-byte range blocks one DATA SET MANAGEMENT command
/// stages in this driver (the range buffer is one allocation).
pub const DSM_MAX_BLOCKS_PER_CMD: u16 = 256;

/// Issue ATA `FLUSH CACHE` (0xE7) or `FLUSH CACHE EXT` (0xEA) on
/// the given port (#841): a non-data command that returns only
/// when the device's volatile write cache has reached the medium.
/// Same per-call DMA page + forget-on-timeout discipline as
/// [`identify_device`] — a flush that did not complete must
/// surface as an error, never as success.
///
/// # Safety
/// `regs` is the HBA the caller owns exclusively; `port_idx < 32`
/// and the port's PortKind was Sata at probe.
pub unsafe fn flush_cache(
    regs: &impl AhciRegs,
    cap: u32,
    port_idx: u8,
    ext: bool,
) -> Result<(), AhciError> {
    let off = port_off(port_idx);
    port_idle(regs, port_idx)?;

    // One 4 KiB DMA page: cmd_list@0x000, fis_recv@0x400,
    // cmd_tbl@0x500. No data buffer — FLUSH CACHE is non-data
    // (PRDT length 0).
    let scratch = alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| AhciError::BarMapFailed)?;
    if cap & CAP_S64A == 0 && scratch.dma_addr().raw() + 4096 > 1u64 << 32 {
        return Err(AhciError::BarMapFailed);
    }
    const OFF_CMD_LIST: u64 = 0x000;
    const OFF_FIS_RECV: u64 = 0x400;
    const OFF_CMD_TBL: u64 = 0x500;
    let cmd_list_dma = scratch.dma_addr_at(OFF_CMD_LIST);
    let fis_recv_dma = scratch.dma_addr_at(OFF_FIS_RECV);
    let cmd_tbl_dma = scratch.dma_addr_at(OFF_CMD_TBL);

    // SAFETY: coherent DMA page, reached through the kernel direct map.
    unsafe {
        core::ptr::write_bytes(scratch.cpu_mut_ptr::<u8>(), 0, 0x600);
        // Command List entry 0: CFL = 5, W = 0, PRDT length = 0.
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_CMD_LIST), 5);
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_CMD_LIST + 4), 0);
        core::ptr::write_volatile(
            scratch.cpu_mut_ptr_at::<u64>(OFF_CMD_LIST + 8),
            cmd_tbl_dma.raw(),
        );
        // CFIS = H2D Register FIS: type 0x27, C bit, opcode
        // FLUSH CACHE EXT (LBA48 devices) or FLUSH CACHE, device
        // byte = LBA mode (0x40), as libata programs it.
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL), 0x27);
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 1), 0x80);
        core::ptr::write_volatile(
            scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 2),
            if ext { 0xEA } else { 0xE7 },
        );
        core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 7), 0x40);
    }

    regs.write32(off, cmd_list_dma.raw() as u32);
    regs.write32(off + 0x04, (cmd_list_dma.raw() >> 32) as u32);
    regs.write32(off + 0x08, fis_recv_dma.raw() as u32);
    regs.write32(off + 0x0C, (fis_recv_dma.raw() >> 32) as u32);
    let serr = regs.read32(off + PORT_SERR);
    regs.write32(off + PORT_SERR, serr);
    regs.write32(off + PORT_IS, 0xFFFF_FFFF);
    let cmd = regs.read32(off + PORT_CMD);
    regs.write32(off + PORT_CMD, cmd | CMD_FRE);
    let cmd = regs.read32(off + PORT_CMD);
    regs.write32(off + PORT_CMD, cmd | CMD_ST);

    compiler_fence(Ordering::SeqCst);
    regs.write32(off + PORT_CI, 1);

    // A flush drains the whole write cache; spinning media can
    // take seconds. Same 30 s budget as the DMA paths.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let ci = regs.read32(off + PORT_CI);
            let tfd = regs.read32(off + PORT_TFD);
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        // The HBA may still own the command; never hand the page
        // back while it can be a DMA target.
        core::mem::forget(scratch);
        return Err(AhciError::ResetTimeout);
    }
    if let Err(e) = port_idle(regs, port_idx) {
        core::mem::forget(scratch);
        return Err(e);
    }
    Ok(())
}

/// Issue ATA `DATA SET MANAGEMENT` (0x06, FEATURE = 0x0001 TRIM)
/// for `ranges` on the given port (#841), chunking the range list
/// into commands of at most `max_blocks` 512-byte range blocks
/// (the device's IDENTIFY word 105 limit) and at most
/// [`DSM_MAX_BLOCKS_PER_CMD`] blocks per command. Each command
/// returns only on completion; a failed chunk aborts the rest
/// (earlier chunks are already trimmed — chunked TRIM is inherently
/// partial, like Linux's per-request discard splitting).
///
/// # Safety
/// `regs` is the HBA the caller owns exclusively; `port_idx < 32`
/// and the port's PortKind was Sata at probe.
pub unsafe fn dsm_trim(
    regs: &impl AhciRegs,
    cap: u32,
    port_idx: u8,
    ranges: &[(u64, u16)],
    max_blocks: u16,
) -> Result<(), AhciError> {
    if ranges.is_empty() {
        return Ok(());
    }
    let blocks_per_cmd = max_blocks.clamp(1, DSM_MAX_BLOCKS_PER_CMD) as usize;
    let alloc_bytes = 0x600 + blocks_per_cmd * 512;
    let off = port_off(port_idx);

    let scratch =
        alloc_coherent(alloc_bytes, DomainId::DRIVER_0).map_err(|_| AhciError::BarMapFailed)?;
    if cap & CAP_S64A == 0 && scratch.dma_addr().raw() + alloc_bytes as u64 > 1u64 << 32 {
        return Err(AhciError::BarMapFailed);
    }
    const OFF_CMD_LIST: u64 = 0x000;
    const OFF_FIS_RECV: u64 = 0x400;
    const OFF_CMD_TBL: u64 = 0x500;
    const OFF_DATA: u64 = 0x600;
    const OFF_PRDT: u64 = OFF_CMD_TBL + 0x80;
    let cmd_list_dma = scratch.dma_addr_at(OFF_CMD_LIST);
    let fis_recv_dma = scratch.dma_addr_at(OFF_FIS_RECV);
    let cmd_tbl_dma = scratch.dma_addr_at(OFF_CMD_TBL);
    let data_dma = scratch.dma_addr_at(OFF_DATA);

    let mut idx = 0usize;
    while idx < ranges.len() {
        let take = (blocks_per_cmd * 64).min(ranges.len() - idx);
        let n_blocks = take.div_ceil(64);
        port_idle(regs, port_idx)?;

        // Stage the range blocks for this chunk.
        // SAFETY: coherent DMA page, reached through the kernel
        // direct map; regions are disjoint and in bounds.
        unsafe {
            core::ptr::write_bytes(scratch.cpu_mut_ptr::<u8>(), 0, 0x600 + n_blocks * 512);
            let mut block = [0u8; 512];
            for b in 0..n_blocks {
                let start = idx + b * 64;
                let end = (start + 64).min(idx + take);
                encode_dsm_range_block(&ranges[start..end], &mut block);
                core::ptr::copy_nonoverlapping(
                    block.as_ptr(),
                    scratch.cpu_mut_ptr_at::<u8>(OFF_DATA + (b * 512) as u64),
                    512,
                );
            }
            // Command List entry 0: CFL = 5, W = 1 (host→device
            // data), PRDT length = 1.
            core::ptr::write_volatile(
                scratch.cpu_mut_ptr_at::<u32>(OFF_CMD_LIST),
                (1u32 << 16) | (1u32 << 6) | 5,
            );
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_CMD_LIST + 4), 0);
            core::ptr::write_volatile(
                scratch.cpu_mut_ptr_at::<u64>(OFF_CMD_LIST + 8),
                cmd_tbl_dma.raw(),
            );
            // CFIS: type 0x27, C bit, opcode 0x06 (DATA SET
            // MANAGEMENT), FEATURE = 0x0001 (TRIM) at +3, device =
            // LBA mode at +7, 16-bit block count at +12/+13 (the
            // EXT-style layout this driver's DMA commands use).
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL), 0x27);
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 1), 0x80);
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 2), 0x06);
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 3), 0x01);
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 7), 0x40);
            core::ptr::write_volatile(
                scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 12),
                (n_blocks & 0xFF) as u8,
            );
            core::ptr::write_volatile(
                scratch.cpu_mut_ptr_at::<u8>(OFF_CMD_TBL + 13),
                ((n_blocks >> 8) & 0xFF) as u8,
            );
            // PRDT entry 0 → the staged range blocks.
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u64>(OFF_PRDT), data_dma.raw());
            core::ptr::write_volatile(scratch.cpu_mut_ptr_at::<u32>(OFF_PRDT + 8), 0);
            core::ptr::write_volatile(
                scratch.cpu_mut_ptr_at::<u32>(OFF_PRDT + 12),
                (n_blocks * 512 - 1) as u32,
            );
        }

        regs.write32(off, cmd_list_dma.raw() as u32);
        regs.write32(off + 0x04, (cmd_list_dma.raw() >> 32) as u32);
        regs.write32(off + 0x08, fis_recv_dma.raw() as u32);
        regs.write32(off + 0x0C, (fis_recv_dma.raw() >> 32) as u32);
        let serr = regs.read32(off + PORT_SERR);
        regs.write32(off + PORT_SERR, serr);
        regs.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = regs.read32(off + PORT_CMD);
        regs.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = regs.read32(off + PORT_CMD);
        regs.write32(off + PORT_CMD, cmd | CMD_ST);

        compiler_fence(Ordering::SeqCst);
        regs.write32(off + PORT_CI, 1);

        let mut errored = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let ci = regs.read32(off + PORT_CI);
                let tfd = regs.read32(off + PORT_TFD);
                if tfd & 0x01 != 0 {
                    errored = true;
                    return true;
                }
                ci & 1 == 0
            },
            narf_time::Deadline::after_ms(30_000),
        );
        if errored || !done {
            core::mem::forget(scratch);
            return Err(AhciError::ResetTimeout);
        }
        if let Err(e) = port_idle(regs, port_idx) {
            core::mem::forget(scratch);
            return Err(e);
        }
        idx += take;
    }
    Ok(())
}

/// Issue ATA `WRITE DMA EXT` (opcode 0x35) for `n_sectors`
/// 512-byte sectors starting at `lba`, sourcing from `data`,
/// staged through the scratch page's data area (≤
/// [`SCRATCH_DATA_MAX`] bytes).
///
/// # Safety
/// Same as `ahci_read_lba`.
pub unsafe fn ahci_write_lba(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
) -> Result<(), AhciError> {
    // SAFETY: forwarded caller contract; the data area is the
    // scratch page's own region past the command structures.
    unsafe {
        ahci_write_lba_xfer(
            ahci,
            port_idx,
            lba,
            n_sectors,
            data,
            DmaStage {
                phys: ahci.scratch_phys() + SCRATCH_DATA_OFF as u64,
                cap: SCRATCH_DATA_MAX,
            },
            false,
        )
    }
}

/// Issue ATA `WRITE DMA FUA EXT` (opcode 0x3D) (#841): like
/// [`ahci_write_lba`], but the device must commit the data to the
/// medium before reporting completion, bypassing its volatile
/// write cache for these sectors. Only valid on devices whose
/// IDENTIFY reports WRITE DMA FUA EXT (word 84 bit 10) — the
/// caller (the block surface) checks.
///
/// # Safety
/// Same as `ahci_read_lba`.
pub unsafe fn ahci_write_lba_fua(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
    stage: DmaStage,
) -> Result<(), AhciError> {
    // SAFETY: forwarded caller contract.
    unsafe { ahci_write_lba_xfer(ahci, port_idx, lba, n_sectors, data, stage, true) }
}

/// Shared WRITE DMA (FUA) EXT body. Command structures live in
/// the controller's scratch page; the payload is staged in
/// `stage` — the scratch page's data area for small transfers, the
/// per-controller transfer buffer for bulk ones (#930). The PRDT
/// carries a single entry, so `n_sectors * 512 <= stage.cap` and
/// `stage.cap` must stay within the PRDT 4 MiB byte-count limit.
///
/// # Safety
/// Same as `ahci_read_lba`; `stage` must name a coherent DMA
/// region of at least `stage.cap` bytes owned by `ahci`.
pub unsafe fn ahci_write_lba_xfer(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
    stage: DmaStage,
    fua: bool,
) -> Result<(), AhciError> {
    let data_buf = stage.phys;
    if n_sectors == 0 || (n_sectors as usize) * 512 > stage.cap {
        return Err(AhciError::BarMapFailed);
    }
    if data.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent per-controller scratch (audit #3 — pre-fix this
    // was alloc_coherent per call, dropped on return; the freed
    // page could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    // Zero the cmd-list / FIS / cmd-table prefix; copy caller payload
    // into the data buffer. Bulk `write_bytes` / `copy_nonoverlapping`
    // rather than per-byte volatile loops — the scratch is coherent
    // DMA memory, not MMIO, and the fence before the CI doorbell below
    // is what publishes these stores before the device can look.
    // SAFETY: coherent DMA reached through the kernel direct map; `data` is a kernel slice that
    // cannot overlap the staging region, and the entry check
    // `n_sectors * 512 <= stage.cap` keeps the copy inside it.
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x600,
        );
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            narf_memory::PhysAddr::new(data_buf).kernel_mut_ptr::<u8>(),
            (n_sectors as usize) * 512,
        );
    }

    // Cmd list slot 0: PRDT length = 1, CFL = 5, W bit = 1 (write).
    // SAFETY: coherent DMA reached through the kernel direct map.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list).kernel_mut_ptr::<u32>(),
            (1u32 << 16) | (1u32 << 6) | 5,
        ); // bit 6 = W
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }

    // CFIS = H2D for WRITE DMA EXT (0x35), or WRITE DMA FUA EXT
    // (0x3D) when `fua` — identical FIS layout, FUA semantics.
    // SAFETY: coherent DMA reached through the kernel direct map.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            if fua { 0x3D } else { 0x35 },
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 4).kernel_mut_ptr::<u8>(),
            (lba & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 5).kernel_mut_ptr::<u8>(),
            ((lba >> 8) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 6).kernel_mut_ptr::<u8>(),
            ((lba >> 16) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 7).kernel_mut_ptr::<u8>(),
            0x40,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 8).kernel_mut_ptr::<u8>(),
            ((lba >> 24) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 9).kernel_mut_ptr::<u8>(),
            ((lba >> 32) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 10).kernel_mut_ptr::<u8>(),
            ((lba >> 40) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 12).kernel_mut_ptr::<u8>(),
            (n_sectors & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 13).kernel_mut_ptr::<u8>(),
            ((n_sectors >> 8) & 0xFF) as u8,
        );
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt).kernel_mut_ptr::<u64>(),
            data_buf,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 8).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 12).kernel_mut_ptr::<u32>(),
            bytes - 1,
        );
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + 0x10, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + 0x38, 1);
    }

    // responsive_spin_until ticks sleep_pumps so cursor/FB stay
    // alive while waiting for WRITE DMA EXT to finish. 30 s
    // wall-clock budget for spinning rust worst-case.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { ahci.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// Issue ATA `READ DMA EXT` (opcode 0x25) for `n_sectors` 512-byte
/// sectors starting at `lba`, copying the result into `out`. `out`
/// must be at least `n_sectors * 512` bytes. The transfer is staged
/// through the scratch page's data area (≤ [`SCRATCH_DATA_MAX`]
/// bytes); bulk callers use [`ahci_read_lba_xfer`] with the
/// per-controller transfer buffer (#930).
///
/// # Safety
/// Same as `identify_device`.
pub unsafe fn ahci_read_lba(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
) -> Result<(), AhciError> {
    // SAFETY: forwarded caller contract; the data area is the
    // scratch page's own region past the command structures.
    unsafe {
        ahci_read_lba_xfer(
            ahci,
            port_idx,
            lba,
            n_sectors,
            out,
            DmaStage {
                phys: ahci.scratch_phys() + SCRATCH_DATA_OFF as u64,
                cap: SCRATCH_DATA_MAX,
            },
        )
    }
}

/// Shared READ DMA EXT body. Command structures live in the
/// controller's scratch page; the payload lands in `stage` before
/// being copied to `out` — the scratch page's data area for small
/// transfers, the per-controller transfer buffer for bulk ones
/// (#930). Single PRDT entry, so `n_sectors * 512 <= stage.cap`.
///
/// # Safety
/// Same as `identify_device`; `stage` must name a coherent DMA
/// region of at least `stage.cap` bytes owned by `ahci`.
pub unsafe fn ahci_read_lba_xfer(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
    stage: DmaStage,
) -> Result<(), AhciError> {
    let data_buf = stage.phys;
    if n_sectors == 0 || (n_sectors as usize) * 512 > stage.cap {
        return Err(AhciError::BarMapFailed);
    }
    if out.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent per-controller scratch (audit #3 — pre-fix this
    // was alloc_coherent per call, dropped on return; the freed
    // page could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    // Bulk `write_bytes`, not a per-byte volatile loop: this ran one
    // `write_volatile` per byte, which the compiler cannot vectorise
    // or turn into a `memset`, so every read paid thousands of
    // separate single-byte stores on the hottest path in the system.
    // Volatility buys nothing here — the scratch is coherent DMA
    // memory, not MMIO, and the fence before the CI doorbell below is
    // what publishes these zeroes before the device is notified.
    // The command prefix and the data staging region are zeroed
    // separately: identical coverage when the staging region is the
    // scratch's own data area, correct when it is the separate
    // transfer buffer.
    // SAFETY: identity-mapped DMA; the prefix extent is the
    // scratch's first 0x600 bytes and the data extent is
    // `n_sectors * 512 <= stage.cap` (checked at entry).
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x600,
        );
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(data_buf).kernel_mut_ptr::<u8>(),
            0,
            (n_sectors as usize) * 512,
        );
    }

    // Cmd list slot 0: PRDT length = 1, CFL = 5 (H2D FIS).
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list).kernel_mut_ptr::<u32>(),
            (1u32 << 16) | 5,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }

    // CFIS: H2D Register FIS for READ DMA EXT.
    //   +0  type = 0x27
    //   +1  bit 7 = C (command)
    //   +2  command = 0x25 (READ DMA EXT)
    //   +3  features (low) = 0
    //   +4  LBA[7:0]
    //   +5  LBA[15:8]
    //   +6  LBA[23:16]
    //   +7  Device = 0x40 (LBA mode)
    //   +8  LBA[31:24]
    //   +9  LBA[39:32]
    //   +10 LBA[47:40]
    //   +11 features (high) = 0
    //   +12 sector count low
    //   +13 sector count high
    //   +14 ICC = 0
    //   +15 Control = 0
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            0x25,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 4).kernel_mut_ptr::<u8>(),
            (lba & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 5).kernel_mut_ptr::<u8>(),
            ((lba >> 8) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 6).kernel_mut_ptr::<u8>(),
            ((lba >> 16) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 7).kernel_mut_ptr::<u8>(),
            0x40,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 8).kernel_mut_ptr::<u8>(),
            ((lba >> 24) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 9).kernel_mut_ptr::<u8>(),
            ((lba >> 32) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 10).kernel_mut_ptr::<u8>(),
            ((lba >> 40) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 12).kernel_mut_ptr::<u8>(),
            (n_sectors & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 13).kernel_mut_ptr::<u8>(),
            ((n_sectors >> 8) & 0xFF) as u8,
        );
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt).kernel_mut_ptr::<u64>(),
            data_buf,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 8).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 12).kernel_mut_ptr::<u32>(),
            bytes - 1,
        );
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + 0x10, 0xFFFF_FFFF); // clear PORT_IS
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + 0x38, 1);
    }

    // responsive_spin_until ticks sleep_pumps so cursor/FB stay
    // alive while waiting for READ DMA EXT to finish. 30 s
    // wall-clock budget for spinning rust worst-case.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { ahci.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }

    // The CI-clear poll above is what makes the device's writes
    // visible; fence so the bulk copy cannot be hoisted above it.
    compiler_fence(Ordering::Acquire);
    // SAFETY: `data_buf` is the base of the DMA area the HBA filled
    // with the read payload (n_sectors*512 ≤ SCRATCH_DATA_MAX and
    // ≤ out.len(), both checked at entry); `out` is a kernel slice
    // that cannot overlap the identity-mapped scratch page. Bulk copy
    // rather than a per-byte volatile loop: the payload is coherent
    // DMA memory, not MMIO, and per-byte volatility defeats
    // vectorisation on the hottest path in the system.
    unsafe {
        core::ptr::copy_nonoverlapping(
            narf_memory::PhysAddr::new(data_buf).kernel_ptr::<u8>(),
            out.as_mut_ptr(),
            (n_sectors as usize) * 512,
        );
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// IRQ-driven sibling of [`ahci_read_lba`]. Identical wire-form +
/// DMA-scratch shape; the only difference is that completion is
/// signalled by an MSI-X / MSI / INTx interrupt walked by
/// [`ahci_isr`] instead of by the host spin-polling PORT_CI.
///
/// Falls back to spin-polling when no IRQ path is wired (i.e. when
/// `AHCI_IRQ_VECTOR` is 0). This keeps the function safe to call
/// even when MSI-X / MSI / INTx negotiation failed at probe.
///
/// # Safety
/// Same as [`ahci_read_lba`].
pub async unsafe fn ahci_read_lba_async(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
) -> Result<(), AhciError> {
    if n_sectors == 0 || (n_sectors as usize) * 512 > SCRATCH_DATA_MAX {
        return Err(AhciError::BarMapFailed);
    }
    if out.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // Bulk zero — see `ahci_read_lba` for why this is not a per-byte
    // volatile loop.
    // SAFETY: identity-mapped DMA; extent ≤ 4096 (checked at entry).
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x600 + (n_sectors as usize) * 512,
        );
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list).kernel_mut_ptr::<u32>(),
            (1u32 << 16) | 5,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            0x25,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 4).kernel_mut_ptr::<u8>(),
            (lba & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 5).kernel_mut_ptr::<u8>(),
            ((lba >> 8) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 6).kernel_mut_ptr::<u8>(),
            ((lba >> 16) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 7).kernel_mut_ptr::<u8>(),
            0x40,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 8).kernel_mut_ptr::<u8>(),
            ((lba >> 24) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 9).kernel_mut_ptr::<u8>(),
            ((lba >> 32) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 10).kernel_mut_ptr::<u8>(),
            ((lba >> 40) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 12).kernel_mut_ptr::<u8>(),
            (n_sectors & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 13).kernel_mut_ptr::<u8>(),
            ((n_sectors >> 8) & 0xFF) as u8,
        );
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt).kernel_mut_ptr::<u64>(),
            data_buf,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 8).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 12).kernel_mut_ptr::<u32>(),
            bytes - 1,
        );
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        // Drain stale PORT_IS so an old latched bit can't get
        // mis-attributed to this command.
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    // Hand off to issue_and_wait_async — it constructs the IRQ
    // waiter BEFORE writing PORT_CI, which closes the race
    // documented in the module header.
    // SAFETY: port set up above; bit 0 = slot 0.
    let r = unsafe { ahci.issue_and_wait_async(port_idx, 1).await };
    r?;

    // The IRQ-signalled completion above is what makes the device's
    // writes visible; fence so the bulk copy cannot be hoisted above
    // it.
    compiler_fence(Ordering::Acquire);
    // SAFETY: `data_buf` is the base of the DMA area the HBA filled
    // with the read payload (n_sectors*512 ≤ SCRATCH_DATA_MAX bytes,
    // checked at entry); `out` is a kernel slice that cannot overlap
    // the identity-mapped scratch page. Bulk copy rather than a
    // per-byte volatile loop — see `ahci_read_lba`.
    unsafe {
        core::ptr::copy_nonoverlapping(
            narf_memory::PhysAddr::new(data_buf).kernel_ptr::<u8>(),
            out.as_mut_ptr(),
            (n_sectors as usize) * 512,
        );
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// IRQ-driven sibling of [`ahci_write_lba`]. Same shape as
/// [`ahci_read_lba_async`].
///
/// # Safety
/// Same as [`ahci_write_lba`].
pub async unsafe fn ahci_write_lba_async(
    ahci: &Ahci,
    port_idx: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
) -> Result<(), AhciError> {
    if n_sectors == 0 || (n_sectors as usize) * 512 > SCRATCH_DATA_MAX {
        return Err(AhciError::BarMapFailed);
    }
    if data.len() < (n_sectors as usize) * 512 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // Bulk zero + payload copy — see `ahci_write_lba` for why these
    // are not per-byte volatile loops.
    // SAFETY: identity-mapped DMA; n_sectors*512 ≤ SCRATCH_DATA_MAX
    // (checked at entry) keeps the copy inside the scratch page, and
    // `data` is a kernel slice that cannot overlap it.
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x600,
        );
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            narf_memory::PhysAddr::new(data_buf).kernel_mut_ptr::<u8>(),
            (n_sectors as usize) * 512,
        );
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        // bit 6 = W (write).
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list).kernel_mut_ptr::<u32>(),
            (1u32 << 16) | (1u32 << 6) | 5,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            0x35,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 4).kernel_mut_ptr::<u8>(),
            (lba & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 5).kernel_mut_ptr::<u8>(),
            ((lba >> 8) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 6).kernel_mut_ptr::<u8>(),
            ((lba >> 16) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 7).kernel_mut_ptr::<u8>(),
            0x40,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 8).kernel_mut_ptr::<u8>(),
            ((lba >> 24) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 9).kernel_mut_ptr::<u8>(),
            ((lba >> 32) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 10).kernel_mut_ptr::<u8>(),
            ((lba >> 40) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 12).kernel_mut_ptr::<u8>(),
            (n_sectors & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 13).kernel_mut_ptr::<u8>(),
            ((n_sectors >> 8) & 0xFF) as u8,
        );
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt).kernel_mut_ptr::<u64>(),
            data_buf,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 8).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 12).kernel_mut_ptr::<u32>(),
            bytes - 1,
        );
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    // SAFETY: port set up above.
    unsafe { ahci.issue_and_wait_async(port_idx, 1).await }?;

    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// Issue ATA `READ FPDMA QUEUED` (NCQ, opcode 0x60) for a single
/// outstanding command on slot `tag` (0..31), reading `n_sectors`
/// 512-byte sectors at `lba`. Polled completion on PORT_CI bit
/// `tag` clearing. Same single-page scratch shape as the non-NCQ
/// variants.
///
/// NCQ wire-form differs from READ DMA EXT (§7.21 of ATA8-ACS): the
/// "sector count" register holds the tag (bits[7:3]) instead of the
/// xfer length, and the xfer length lives in the features register.
/// Tag-zero scheduling ("priority 0, normal") is used here.
///
/// `pmp` is the port-multiplier port number (0 for direct-attach).
///
/// # Safety
/// Same as `ahci_read_lba`. Caller asserts `tag < 32`.
pub unsafe fn ahci_read_lba_ncq(
    ahci: &Ahci,
    port_idx: u8,
    pmp: u8,
    tag: u8,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
) -> Result<(), AhciError> {
    if tag >= 32
        || n_sectors == 0
        || (n_sectors as usize) * 512 > SCRATCH_DATA_MAX
        || out.len() < (n_sectors as usize) * 512
    {
        return Err(AhciError::BarMapFailed);
    }
    // SAFETY: caller-asserted.
    unsafe {
        ahci_lba_ncq(
            ahci,
            port_idx,
            pmp,
            tag,
            /*write=*/ false,
            lba,
            n_sectors,
            out,
            &[],
        )
    }
}

/// Issue ATA `WRITE FPDMA QUEUED` (NCQ, opcode 0x61). Mirror of
/// `ahci_read_lba_ncq` for outbound transfers.
///
/// # Safety
/// Same as `ahci_write_lba`.
pub unsafe fn ahci_write_lba_ncq(
    ahci: &Ahci,
    port_idx: u8,
    pmp: u8,
    tag: u8,
    lba: u64,
    n_sectors: u16,
    data: &[u8],
) -> Result<(), AhciError> {
    if tag >= 32
        || n_sectors == 0
        || (n_sectors as usize) * 512 > SCRATCH_DATA_MAX
        || data.len() < (n_sectors as usize) * 512
    {
        return Err(AhciError::BarMapFailed);
    }
    let mut sink = [0u8; 0];
    // SAFETY: caller-asserted.
    unsafe {
        ahci_lba_ncq(
            ahci, port_idx, pmp, tag, /*write=*/ true, lba, n_sectors, &mut sink, data,
        )
    }
}

// All parameters map directly to AHCI NCQ FIS and PRD fields; no grouping is natural.
#[allow(clippy::too_many_arguments)]
unsafe fn ahci_lba_ncq(
    ahci: &Ahci,
    port_idx: u8,
    pmp: u8,
    tag: u8,
    write: bool,
    lba: u64,
    n_sectors: u16,
    out: &mut [u8],
    data_in: &[u8],
) -> Result<(), AhciError> {
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Persistent shared scratch (audit #3 — pre-fix this was
    // alloc_coherent per call, dropped on return; freed page
    // could be reused while AHCI still had a delayed DMA in
    // flight under AMD-Vi).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;
    let data_buf = base + 0x600;
    // Zero scratch + (for writes) copy caller payload in. Bulk ops —
    // see `ahci_read_lba` for why these are not per-byte volatile
    // loops.
    // SAFETY: identity-mapped DMA; the public NCQ wrappers check
    // n_sectors*512 ≤ SCRATCH_DATA_MAX, keeping the copy inside the
    // scratch page, and `data_in` is a kernel slice that cannot
    // overlap it.
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x600,
        );
        if write {
            core::ptr::copy_nonoverlapping(
                data_in.as_ptr(),
                narf_memory::PhysAddr::new(data_buf).kernel_mut_ptr::<u8>(),
                (n_sectors as usize) * 512,
            );
        }
    }

    // Cmd-list slot for `tag`. Each command-header is 32 bytes; we
    // only program slot `tag` so seek to its base.
    let slot = cmd_list + (tag as u64) * 32;
    // CFL = 5 (H2D FIS = 5 DWORDs), W bit = 1 if writing, P bit
    // (prefetchable) = 0 for NCQ. PRDT length = 1.
    let header_w0 = (1u32 << 16) | (if write { 1u32 << 6 } else { 0 }) | 5;
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(slot).kernel_mut_ptr::<u32>(),
            header_w0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(slot + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(slot + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }

    // CFIS H2D (FIS type 0x27) for FPDMA QUEUED:
    //   +0  type = 0x27
    //   +1  bit 7 = C (command), bits[3:0] = PMP target
    //   +2  command = 0x60 (READ) or 0x61 (WRITE)
    //   +3  features (low) = sector count low
    //   +4..7 LBA[23..0] + Device (0x40 = LBA)
    //   +8..10 LBA[47..24]
    //   +11 features (high) = sector count high
    //   +12 sector_count register = (tag << 3) | priority
    //   +13 0 (auxiliary)
    //   +14 ICC = 0
    //   +15 Control = 0
    let opcode = if write { 0x61u8 } else { 0x60u8 };
    let sec_lo = (n_sectors & 0xFF) as u8;
    let sec_hi = ((n_sectors >> 8) & 0xFF) as u8;
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80 | (pmp & 0x0F),
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            opcode,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            sec_lo,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 4).kernel_mut_ptr::<u8>(),
            (lba & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 5).kernel_mut_ptr::<u8>(),
            ((lba >> 8) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 6).kernel_mut_ptr::<u8>(),
            ((lba >> 16) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 7).kernel_mut_ptr::<u8>(),
            0x40,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 8).kernel_mut_ptr::<u8>(),
            ((lba >> 24) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 9).kernel_mut_ptr::<u8>(),
            ((lba >> 32) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 10).kernel_mut_ptr::<u8>(),
            ((lba >> 40) & 0xFF) as u8,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 11).kernel_mut_ptr::<u8>(),
            sec_hi,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 12).kernel_mut_ptr::<u8>(),
            tag << 3,
        );
    }
    let prdt = cmd_tbl + 0x80;
    let bytes = (n_sectors as u32) * 512;
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt).kernel_mut_ptr::<u64>(),
            data_buf,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 8).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(prdt + 12).kernel_mut_ptr::<u32>(),
            bytes - 1,
        );
    }

    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + 0x10, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    // Set PORT_SACT bit `tag` BEFORE PORT_CI to mark this command
    // queued (NCQ requirement, AHCI 1.3.1 §5.3.13).
    compiler_fence(Ordering::SeqCst);
    let bit = 1u32 << tag;
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + 0x34, bit); // PORT_SACT
        ahci.mmio.write32(off + 0x38, bit); // PORT_CI
    }

    // responsive_spin_until ticks sleep_pumps so cursor/FB stay
    // alive during the user-issued R/W DMA. 30 s wall-clock budget
    // for spinning rust worst-case.
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: identity-mapped MMIO.
            let ci = unsafe { ahci.mmio.read32(off + 0x38) };
            // SAFETY: same.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & bit == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }

    // For reads, copy back. The CI-clear poll above is what makes the
    // device's writes visible; fence so the bulk copy cannot be
    // hoisted above it.
    if !write {
        compiler_fence(Ordering::Acquire);
        // SAFETY: `data_buf` is the base of the DMA area the HBA
        // filled for this read (n_sectors*512 ≤ SCRATCH_DATA_MAX and
        // ≤ out.len(), both checked by the public wrapper); `out` is a
        // kernel slice that cannot overlap the identity-mapped scratch
        // page. Bulk copy rather than a per-byte volatile loop — see
        // `ahci_read_lba`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                narf_memory::PhysAddr::new(data_buf).kernel_ptr::<u8>(),
                out.as_mut_ptr(),
                (n_sectors as usize) * 512,
            );
        }
    }
    // SAFETY: caller-asserted.
    let _ = unsafe { ahci.port_idle(port_idx) };
    // (no scratch drop needed — buffer is persistent now)
    Ok(())
}

/// Snapshot of port-multiplier topology behind a port whose
/// `PortKind` was reported as `Pmp` at probe.
///
/// Per SATA 3.x PMP spec §10.3, the host queries the multiplier's
/// GSCR[2] (Number of Device Ports) to learn how many downstream
/// ports it exposes; the GSCR registers are read via READ PORT
/// MULTIPLIER (0xE4). This snapshot is what `discover_pmp_topology`
/// returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PmpTopology {
    /// Number of downstream ports advertised by the multiplier.
    pub num_ports: u8,
    /// Port-multiplier vendor id (GSCR[0] low half).
    pub vendor: u16,
    /// Port-multiplier product id (GSCR[0] high half).
    pub product: u16,
    /// PMP revision byte (GSCR[1] bits[15:8]).
    pub revision: u8,
    /// Raw GSCR[64] Features register.
    pub features: u32,
}

// ── PMP GSCR indices (SATA 3.x PMP spec §10.3 / Linux ata.h) ────────
/// GSCR[0] = ProductId in high 16 bits, VendorId in low 16 bits.
const GSCR_PROD_ID: u8 = 0;
/// GSCR[1] = Revision: bits[15:8] = major, bits[7:0] = minor.
const GSCR_REV: u8 = 1;
/// GSCR[2] = Port Info: bits[3:0] = number of device ports.
const GSCR_PORT_INFO: u8 = 2;
/// GSCR[64] = Features (optional capability flags).
const GSCR_FEAT: u8 = 64;

/// PMP control port address — READ PORT MULTIPLIER commands that
/// target the PMP's own register set use port-address 0x0F.
/// Reference: SATA Port Multiplier Spec §6.2.2.
const PMP_CTRL_PORT: u8 = 0x0F;

/// Issue one READ PORT MULTIPLIER command (ATA opcode 0xE4) to read
/// GSCR register `reg` from the PMP behind `port_idx`. Returns the
/// 32-bit register value.
///
/// Wire format (SATA PMP spec §6.2 / ATA8-ACS §7.43):
///
///   CFIS (H2D Register FIS):
///     +0  type   = 0x27 (Register H2D)
///     +1  C=1    | PMP port = 0x0F (control port)
///     +2  opcode = 0xE4 (READ PORT MULTIPLIER)
///     +3  features = GSCR register index
///     +12 sector-count = 0 (NODATA)
///
///   Response (D2H):
///     nsect  = val[7:0]
///     lbal   = val[15:8]
///     lbam   = val[23:16]
///     lbah   = val[31:24]
///
/// Reference: Linux `drivers/ata/libata-pmp.c::sata_pmp_read`, which
/// sets `tf.feature = reg; tf.device = link->pmp` and reads back
/// `tf.nsect | tf.lbal<<8 | tf.lbam<<16 | tf.lbah<<24`.
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`.
pub unsafe fn pmp_read_gscr(ahci: &Ahci, port_idx: u8, reg: u8) -> Result<u32, AhciError> {
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;

    // Stop port if running.
    // SAFETY: `pmp_read_gscr`'s contract guarantees the caller owns the HBA
    // exclusively and `port_idx < 32`, which is exactly `port_idle`'s contract.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { ahci.port_idle(port_idx) };

    // Use the persistent scratch at the same layout as identify_device
    // (cmd_list@0x000, fis_recv@0x400, cmd_tbl@0x500, data_buf@0x600).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;

    // Zero the used range. Bulk `write_bytes` — coherent DMA, not
    // MMIO; the fence before the CI doorbell publishes it.
    // SAFETY: identity-mapped DMA, extent within the 4 KiB scratch.
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x500 + 64,
        );
    }

    // Command-list header 0: PRDT length = 0 (NODATA), CFL = 5.
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list).kernel_mut_ptr::<u32>(),
            5,
        ); // PRDT_LEN=0, CFL=5
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }

    // CFIS: H2D Register FIS for READ PORT MULTIPLIER (0xE4).
    //   +0  type = 0x27
    //   +1  C=1 | PMP_port = 0x0F  → 0x80 | 0x0F = 0x8F
    //   +2  command = 0xE4
    //   +3  features = GSCR register index
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80 | PMP_CTRL_PORT,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            0xE4,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            reg,
        );
    }

    // Program port CLB / FB.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + 0x38, 1); // issue slot 0
    }

    // Poll for completion (5 s; NODATA round-trips in microseconds).
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: `off` is this port's register block (port_idx < 32, so
            // within the mapped HBA BAR) and PORT_CI is a valid port-register
            // offset, so the read is in-range; we own the HBA exclusively.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let ci = unsafe { ahci.mmio.read32(off + PORT_CI) };
            // SAFETY: same port register block; 0x20 is PORT_TFD, in-range.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(5_000),
    );
    if errored || !done {
        // SAFETY: caller owns the HBA exclusively and `port_idx < 32`, matching
        // `port_idle`'s contract.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let _ = unsafe { ahci.port_idle(port_idx) };
        return Err(AhciError::ResetTimeout);
    }

    // The D2H Register FIS is deposited at fis_recv + 0x40 (D2H FIS
    // area in the received FIS structure, AHCI 1.3.1 §4.2.1.3).
    // Bytes at the D2H FIS:
    //   +0  type (0x34)
    //   +1  misc
    //   +2  status
    //   +3  error
    //   +4  LBA[7:0]   = nsect
    //   +5  LBA[15:8]  = lbal
    //   +6  LBA[23:16] = lbam
    //   +8  LBA[31:24] = lbah
    // For READ PORT MULTIPLIER the returned value occupies:
    //   nsect = val[7:0], lbal = val[15:8], lbam = val[23:16],
    //   lbah = val[31:24].  Reference: Linux libata-pmp.c line 57.
    let d2h = fis_recv + 0x40;
    // SAFETY: `fis_recv` is the identity-mapped received-FIS region of the
    // scratch DMA page that the HBA wrote the D2H Register FIS into; +0x40 is
    // the D2H FIS area and offsets 4..=8 are within the 256-byte FIS structure.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let val = unsafe {
        let nsect =
            core::ptr::read_volatile(narf_memory::PhysAddr::new(d2h + 4).kernel_ptr::<u8>()) as u32;
        let lbal =
            core::ptr::read_volatile(narf_memory::PhysAddr::new(d2h + 5).kernel_ptr::<u8>()) as u32;
        let lbam =
            core::ptr::read_volatile(narf_memory::PhysAddr::new(d2h + 6).kernel_ptr::<u8>()) as u32;
        let lbah =
            core::ptr::read_volatile(narf_memory::PhysAddr::new(d2h + 8).kernel_ptr::<u8>()) as u32;
        nsect | (lbal << 8) | (lbam << 16) | (lbah << 24)
    };

    // SAFETY: `pmp_read_gscr`'s contract guarantees exclusive HBA ownership and
    // `port_idx < 32`, satisfying `port_idle`'s contract.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { ahci.port_idle(port_idx) };
    Ok(val)
}

/// Discover the topology behind a PMP-attached port. Returns `None`
/// if the port wasn't a PMP at probe.
///
/// Issues READ PORT MULTIPLIER (ATA 0xE4) commands to read GSCR[0]
/// (ProductId/VendorId), GSCR[1] (Revision), GSCR[2] (Port count),
/// and GSCR[64] (Features). Topology is reported regardless of
/// whether all GSCR reads succeed — partial failures yield zeroed
/// fields.
///
/// Reference: Linux `drivers/ata/libata-pmp.c::sata_pmp_read_gscr`
/// which reads registers {0,1,2,32,33,64,96} on attach.
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`.
pub unsafe fn discover_pmp_topology(ahci: &Ahci, port_idx: u8) -> Option<PmpTopology> {
    let info = ahci.ports.iter().find(|p| p.index == port_idx)?;
    if info.kind != PortKind::Pmp {
        return None;
    }

    // Each `pmp_read_gscr` below requires exclusive HBA ownership and
    // `port_idx < 32`; `discover_pmp_topology`'s own `# Safety` contract
    // guarantees both, so forwarding `port_idx` unchanged is sound.
    // GSCR[0] = ProductId[31:16] | VendorId[15:0]
    // SAFETY: see the comment above; contract forwarded from this fn.
    let prod_id = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_PROD_ID) }.unwrap_or(0);
    // GSCR[1] = Revision
    // SAFETY: see above; exclusive HBA, `port_idx < 32`.
    let rev_raw = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_REV) }.unwrap_or(0);
    // GSCR[2] = bits[3:0] = number of device ports
    // SAFETY: see above; exclusive HBA, `port_idx < 32`.
    let port_info = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_PORT_INFO) }.unwrap_or(0);
    // GSCR[64] = Features
    // SAFETY: see above; exclusive HBA, `port_idx < 32`.
    let features = unsafe { pmp_read_gscr(ahci, port_idx, GSCR_FEAT) }.unwrap_or(0);

    Some(PmpTopology {
        vendor: (prod_id & 0xFFFF) as u16,
        product: (prod_id >> 16) as u16,
        // Revision major byte: bits[15:8] per Linux ata.h sata_pmp_gscr_rev macro.
        revision: ((rev_raw >> 8) & 0xFF) as u8,
        // bits[3:0] = number of device ports.
        num_ports: (port_info & 0x0F) as u8,
        features,
    })
}

/// Decode the model-number string from an IDENTIFY DEVICE response.
/// ATA strings are byte-swapped per pair (ATA-8 §7.16.7.36): byte 54
/// = char 0 high, byte 55 = char 0 low, etc. 40 bytes total.
///
/// ATA word 27 = byte offset 54; 20 words (40 bytes) for the model.
pub fn identify_model(id: &[u8; 512]) -> [u8; 40] {
    let mut out = [b' '; 40];
    for i in 0..20 {
        out[i * 2] = id[54 + i * 2 + 1];
        out[i * 2 + 1] = id[54 + i * 2];
    }
    out
}

/// Decode an ATA string field (byte-swapped per pair, space/NUL
/// padded) into a trimmed `String`. Same encoding as
/// [`identify_model`]; used for the registry's `DiskIdentity` (#931).
fn ata_string(id: &[u8; 512], first_word: usize, words: usize) -> alloc::string::String {
    let mut bytes = alloc::vec::Vec::with_capacity(words * 2);
    for i in 0..words {
        bytes.push(id[(first_word + i) * 2 + 1]);
        bytes.push(id[(first_word + i) * 2]);
    }
    while matches!(bytes.last(), Some(b' ' | 0)) {
        bytes.pop();
    }
    alloc::string::String::from_utf8_lossy(&bytes).into_owned()
}

/// IDENTIFY serial number (words 10–19), trimmed.
pub fn identify_serial(id: &[u8; 512]) -> alloc::string::String {
    ata_string(id, 10, 10)
}

/// IDENTIFY firmware revision (words 23–26), trimmed.
pub fn identify_firmware(id: &[u8; 512]) -> alloc::string::String {
    ata_string(id, 23, 4)
}

/// IDENTIFY model string (words 27–46), trimmed.
pub fn identify_model_string(id: &[u8; 512]) -> alloc::string::String {
    ata_string(id, 27, 20)
}

/// Extract the LBA-28 addressable sector count from an IDENTIFY
/// DEVICE response (ATA-8 §7.16 word 60–61, byte offsets 120–123).
/// Returns 0 if 28-bit LBA is not supported. A non-zero value here
/// always means at least 28-bit LBA is available.
pub fn identify_lba28_capacity(id: &[u8; 512]) -> u32 {
    // Word 60 is low word, word 61 is high word (LE pair).
    let lo = u16::from_le_bytes([id[120], id[121]]) as u32;
    let hi = u16::from_le_bytes([id[122], id[123]]) as u32;
    (hi << 16) | lo
}

/// Extract the LBA-48 addressable sector count from an IDENTIFY
/// DEVICE response (ATA-8 §7.16 words 100–103, byte offsets
/// 200–207). Words 82–83 (bytes 164–167) bit 10 of word 83 gates
/// LBA-48 support. Returns 0 if device does not support 48-bit LBA.
pub fn identify_lba48_capacity(id: &[u8; 512]) -> u64 {
    // Word 83 bit 10 = LBA-48 supported (ATA-8 §7.16.7.83 table 21).
    let word83 = u16::from_le_bytes([id[166], id[167]]);
    if word83 & (1 << 10) == 0 {
        return 0;
    }
    // Words 100..103 = 64-bit total LBA count (LE quad-word).
    let b = &id[200..208];
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// User-addressable sectors (Linux `ata_id_n_sectors` for an LBA
/// device): the LBA48 count when word 83 reports 48-bit support and it
/// is non-zero, else the LBA28 count.
pub fn identify_n_sectors(id: &[u8; 512]) -> u64 {
    let lba48 = identify_lba48_capacity(id);
    if lba48 != 0 {
        lba48
    } else {
        identify_lba28_capacity(id) as u64
    }
}

/// Extract the supported-feature bitmask from IDENTIFY DEVICE words
/// 82 (byte 164) and 83 (byte 166). The upper byte of word 83 must
/// read `0x40`/`0xC0` (validity marker); if it doesn't, word 83 is
/// invalid and only word 82's low 16 bits are returned.
/// Returns `(word82, word83)` as raw values for further decoding.
pub fn identify_features(id: &[u8; 512]) -> (u16, u16) {
    let w82 = u16::from_le_bytes([id[164], id[165]]);
    let w83 = u16::from_le_bytes([id[166], id[167]]);
    (w82, w83)
}

// ── ATAPI ─────────────────────────────────────────────────────────────

/// Direction of a DMA transfer associated with an ATAPI PACKET command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtapiDmaDir {
    /// No data phase (e.g. TEST UNIT READY).
    None,
    /// Device-to-host (e.g. READ(10), READ CAPACITY).
    DeviceToHost,
    /// Host-to-device (e.g. WRITE(10)).
    HostToDevice,
}

/// Send an arbitrary SCSI CDB (12 or 16 bytes) to an ATAPI device
/// using the ATA PACKET command (opcode 0xA0). ATAPI devices wrap
/// SCSI CDBs inside an ATA PACKET FIS: the host sends the 12/16-byte
/// CDB via the ACMD field of the command table, and the controller
/// handles the DMA data phase.
///
/// Wire format (AHCI 1.3.1 §7.5 / ATA8-ACS §7.18 PACKET command):
///
///   CFIS (H2D Register FIS):
///     +0  type   = 0x27 (Register H2D)
///     +1  C=1    | PMP port (usually 0)
///     +2  opcode = 0xA0 (ATA PACKET)
///     +3  features: bit 0 = DMA (1) or PIO (0),
///                   bit 2 = DMADIR (1 = D2H / 0 = H2D)
///
///   ACMD (command-table +0x40, 16 bytes): the SCSI CDB.
///
/// Reference: Linux `drivers/ata/libata-scsi.c` ATAPI command tables
/// and `include/linux/libata.h` for the ATAPI protocol constants.
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`
/// and the port's `PortKind` was `Atapi` at probe. `buf_phys` must be
/// a valid DMA-accessible physical address with at least `buf_bytes`
/// bytes mapped; pass 0 / 0 for NODATA commands.
pub unsafe fn atapi_send_cdb(
    ahci: &Ahci,
    port_idx: u8,
    cdb: &[u8],
    dir: AtapiDmaDir,
    buf_phys: u64,
    buf_bytes: u32,
) -> Result<(), AhciError> {
    if cdb.len() != 12 && cdb.len() != 16 {
        return Err(AhciError::BarMapFailed);
    }
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;

    // SAFETY: `atapi_send_cdb`'s contract guarantees exclusive HBA ownership and
    // `port_idx < 32`, which is what `port_idle` requires.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let _ = unsafe { ahci.port_idle(port_idx) };

    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let cmd_list = base;
    let fis_recv = base + 0x400;
    let cmd_tbl = base + 0x500;

    // Zero command-list + FIS receive area + command table. Bulk
    // `write_bytes` — coherent DMA, not MMIO; the fence before the CI
    // doorbell publishes it.
    // SAFETY: identity-mapped DMA, extent within the 4 KiB scratch.
    unsafe {
        core::ptr::write_bytes(
            narf_memory::PhysAddr::new(base).kernel_mut_ptr::<u8>(),
            0,
            0x500 + 0x90,
        );
    }

    // Command-list header 0.
    // Bit 5 (A) = ATAPI (marks the ACMD field in the command table).
    // W bit (bit 6) = 1 for H2D writes, 0 for D2H reads.
    // PRDT length = 1 if data transfer, 0 if NODATA.
    // Reference: AHCI 1.3.1 §4.2.3.1, Table 4.
    let prdt_len = if dir == AtapiDmaDir::None { 0u32 } else { 1u32 };
    let w_bit: u32 = if dir == AtapiDmaDir::HostToDevice {
        1 << 6
    } else {
        0
    };
    let header_w0: u32 = (prdt_len << 16) | w_bit | (1 << 5) | 5; // A=1, CFL=5
                                                                  // SAFETY: coherent DMA page, reached through the kernel direct map.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list).kernel_mut_ptr::<u32>(),
            header_w0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 4).kernel_mut_ptr::<u32>(),
            0,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_list + 8).kernel_mut_ptr::<u64>(),
            cmd_tbl,
        );
    }

    // CFIS (H2D Register FIS, 20 bytes at cmd_tbl+0x00).
    //   features byte: bit 0 = DMA, bit 2 = DMADIR (1=D2H, 0=H2D).
    // Reference: ATA8-ACS Table 101 (PACKET command FIS).
    let feat = match dir {
        AtapiDmaDir::None => 0x00u8,
        AtapiDmaDir::DeviceToHost => 0x01 | 0x04, // DMA | DMADIR=D2H
        AtapiDmaDir::HostToDevice => 0x01,        // DMA only
    };
    // SAFETY: identity-mapped DMA.
    unsafe {
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl).kernel_mut_ptr::<u8>(),
            0x27,
        );
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 1).kernel_mut_ptr::<u8>(),
            0x80,
        ); // C=1, PMP=0
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 2).kernel_mut_ptr::<u8>(),
            0xA0,
        ); // ATA PACKET
        core::ptr::write_volatile(
            narf_memory::PhysAddr::new(cmd_tbl + 3).kernel_mut_ptr::<u8>(),
            feat,
        );
    }

    // ACMD (command-table +0x40, 16 bytes): copy the SCSI CDB.
    // SAFETY: same DMA page.
    unsafe {
        for (i, &b) in cdb.iter().enumerate() {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(cmd_tbl + 0x40 + i as u64).kernel_mut_ptr::<u8>(),
                b,
            );
        }
    }

    // PRDT entry 0 at cmd_tbl+0x80 (only if data transfer).
    let prdt = cmd_tbl + 0x80;
    if dir != AtapiDmaDir::None && buf_bytes > 0 {
        // SAFETY: same DMA page.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(prdt).kernel_mut_ptr::<u64>(),
                buf_phys,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(prdt + 8).kernel_mut_ptr::<u32>(),
                0,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(prdt + 12).kernel_mut_ptr::<u32>(),
                buf_bytes - 1,
            );
        }
    }

    // Program port CLB / FB and start.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off, cmd_list as u32);
        ahci.mmio.write32(off + 0x04, (cmd_list >> 32) as u32);
        ahci.mmio.write32(off + 0x08, fis_recv as u32);
        ahci.mmio.write32(off + 0x0C, (fis_recv >> 32) as u32);
        let serr = ahci.mmio.read32(off + PORT_SERR);
        ahci.mmio.write32(off + PORT_SERR, serr);
        ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_FRE);
        let cmd = ahci.mmio.read32(off + PORT_CMD);
        ahci.mmio.write32(off + PORT_CMD, cmd | CMD_ST);
    }

    compiler_fence(Ordering::SeqCst);
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + PORT_CI, 1);
    }

    // Poll for completion (30 s — optical drives can be slow).
    let mut errored = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: `off` addresses this port's register block (port_idx < 32,
            // inside the mapped HBA BAR); PORT_CI is a valid port-register
            // offset and we own the HBA exclusively.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let ci = unsafe { ahci.mmio.read32(off + PORT_CI) };
            // SAFETY: same port register block; 0x20 is PORT_TFD, in-range.
            let tfd = unsafe { ahci.mmio.read32(off + 0x20) };
            if tfd & 0x01 != 0 {
                errored = true;
                return true;
            }
            ci & 1 == 0
        },
        narf_time::Deadline::after_ms(30_000),
    );
    // SAFETY: exclusive HBA ownership and `port_idx < 32` per this fn's contract.
    let _ = unsafe { ahci.port_idle(port_idx) };
    if errored || !done {
        return Err(AhciError::ResetTimeout);
    }
    Ok(())
}

/// Issue SCSI READ CAPACITY(10) (CDB opcode 0x25) to an ATAPI device
/// and decode the response: returns `(block_count, block_size)`.
///
/// READ CAPACITY(10) response (8 bytes, big-endian):
///   +0..3  last logical block address (LBA of last sector)
///   +4..7  block length in bytes
///
/// Reference: SPC-4 §6.18 / Linux `drivers/ata/libata-scsi.c::
/// ata_scsiop_read_cap`.
///
/// # Safety
/// Same as `atapi_send_cdb`. `port_idx` must be an ATAPI port.
pub unsafe fn read_atapi_capacity(ahci: &Ahci, port_idx: u8) -> Result<(u32, u32), AhciError> {
    // Allocate the 8-byte response in the persistent scratch at
    // data_buf (offset 0x600, safe since scratch is 4 KiB).
    let base = ahci.scratch_phys();
    if base == 0 {
        return Err(AhciError::BarMapFailed);
    }
    let data_buf = base + 0x600;

    // Zero the response area.
    // SAFETY: identity-mapped DMA.
    unsafe {
        for i in 0..8u64 {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(data_buf + i).kernel_mut_ptr::<u8>(),
                0,
            );
        }
    }

    // SCSI READ CAPACITY(10) CDB (12-byte padded form for ATAPI).
    // Opcode 0x25, all other bytes zero (LBA=0, PMI=0).
    let cdb = [0x25u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // SAFETY: caller-asserted ATAPI port.
    unsafe { atapi_send_cdb(ahci, port_idx, &cdb, AtapiDmaDir::DeviceToHost, data_buf, 8) }?;

    // Decode the 8-byte big-endian response.
    // SAFETY: identity-mapped DMA.
    let (last_lba, block_size) = unsafe {
        let last_lba = u32::from_be_bytes([
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf).kernel_ptr::<u8>()),
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 1).kernel_ptr::<u8>()),
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 2).kernel_ptr::<u8>()),
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 3).kernel_ptr::<u8>()),
        ]);
        let block_size = u32::from_be_bytes([
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 4).kernel_ptr::<u8>()),
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 5).kernel_ptr::<u8>()),
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 6).kernel_ptr::<u8>()),
            core::ptr::read_volatile(narf_memory::PhysAddr::new(data_buf + 7).kernel_ptr::<u8>()),
        ]);
        (last_lba, block_size)
    };

    // block_count = last_lba + 1 (READ CAPACITY returns the LBA of the
    // *last* addressable block, not the total count).
    Ok((last_lba.wrapping_add(1), block_size))
}

/// Issue SCSI READ(10) (CDB opcode 0x28) to an ATAPI optical drive,
/// reading `count` blocks starting at `lba`.
///
/// `buf_phys` must be a valid DMA-accessible physical address with at
/// least `count * block_size` bytes.
///
/// CDB layout (SBC-3 §5.8 READ(10)):
///   +0   opcode = 0x28
///   +1   RD_PROTECT | FUA | DPO | RARC (all zero for plain read)
///   +2..5 LBA (big-endian u32)
///   +6   group number (0)
///   +7..8 transfer length (big-endian u16)
///   +9   control (0)
///
/// # Safety
/// Same as `atapi_send_cdb`.
pub unsafe fn read_atapi_lba(
    ahci: &Ahci,
    port_idx: u8,
    lba: u32,
    count: u16,
    buf_phys: u64,
    buf_bytes: u32,
) -> Result<(), AhciError> {
    // SCSI READ(10) packed into 12 bytes (ATAPI CDB length).
    let cdb = [
        0x28u8,                      // READ(10) opcode
        0x00,                        // flags
        ((lba >> 24) & 0xFF) as u8,  // LBA[31:24]
        ((lba >> 16) & 0xFF) as u8,  // LBA[23:16]
        ((lba >> 8) & 0xFF) as u8,   // LBA[15:8]
        (lba & 0xFF) as u8,          // LBA[7:0]
        0x00,                        // group number
        ((count >> 8) & 0xFF) as u8, // transfer length high
        (count & 0xFF) as u8,        // transfer length low
        0x00,                        // control
        0x00,                        // padding
        0x00,                        // padding
    ];

    // SAFETY: caller-asserted ATAPI port.
    unsafe {
        atapi_send_cdb(
            ahci,
            port_idx,
            &cdb,
            AtapiDmaDir::DeviceToHost,
            buf_phys,
            buf_bytes,
        )
    }
}

// ── Hot-plug / hot-unplug ──────────────────────────────────────────────

/// PORT_IS bit 22 — PHYRDY change interrupt status (W1C).
/// AHCI 1.3.1 §3.3.5 Table 11: "PhyRdy Change Status" is bit 22.
pub const PORT_IS_PHYRDY: u32 = 1 << 22;

/// PORT_IE bit 22 — PHYRDY change interrupt enable.
pub const PORT_IE_PHYRDY: u32 = 1 << 22;

/// SERR bit 16 — PHY Ready change (N bit, "PHY RDY Changed").
/// Set by the SATA PHY when the link transitions between present and
/// absent (both directions). W1C. Reference: Linux ata.h
/// `SERR_PHYRDY_CHG = (1 << 16)`.
pub const SERR_PHYRDY_CHG: u32 = 1 << 16;

/// Hot-plug state for a single port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortLinkState {
    /// No device; PHY link is down.
    Disconnected,
    /// Device present, PHY link established.
    Connected {
        /// Detected device kind after re-IDENTIFY.
        kind: PortKind,
    },
}

/// Enable the PHYRDY interrupt on a port by setting PORT_IE bit 22.
///
/// Call once at bring-up and again after each handled PHYRDY event
/// so the next link transition can fire. Not set by the ISR itself
/// to avoid re-enabling before the link state settles.
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`.
pub unsafe fn port_enable_phyrdy_irq(ahci: &Ahci, port_idx: u8) {
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;
    // SAFETY: identity-mapped MMIO.
    let ie = unsafe { ahci.mmio.read32(off + PORT_IE) };
    // SAFETY: same.
    unsafe {
        ahci.mmio.write32(off + PORT_IE, ie | PORT_IE_PHYRDY);
    }
}

/// Handle a PHYRDY change event on `port_idx`.
///
/// Reads PORT_SSTS.DET to decide link direction:
///
/// - **DET = 3** (link-up): clears SERR, issues COMRESET via
///   `port_reset`, re-reads PORT_SIG + PORT_SSTS, returns
///   `PortLinkState::Connected { kind }`.
/// - **DET != 3** (link-down): clears PORT_IS, re-enables PHYRDY IRQ,
///   returns `PortLinkState::Disconnected`.
///
/// The caller is responsible for updating its port-state table and
/// registering / deregistering the `BlockDevice` instance.
///
/// Reference: Linux `drivers/ata/libahci.c::ahci_handle_port_interrupt`
/// (PHYRDY dispatch) and `libata-eh.c::ata_eh_handle_dev_fail`
/// (hot-unplug teardown).
///
/// # Safety
/// Caller owns the HBA + the named port exclusively; `port_idx < 32`.
pub unsafe fn handle_phyrdy_change(ahci: &Ahci, port_idx: u8) -> PortLinkState {
    let off = PORT_BASE_OFF + (port_idx as u64) * PORT_STRIDE;

    // Clear the PHYRDY SERR.N bit (W1C) so the PHY can re-latch the
    // next event. Reference: AHCI 1.3.1 §3.3.12.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        ahci.mmio.write32(off + PORT_SERR, SERR_PHYRDY_CHG);
    }

    // Read PORT_SSTS to determine link direction.
    // SAFETY: same.
    let ssts = unsafe { ahci.mmio.read32(off + PORT_SSTS) };
    let (det, _ipm) = ssts_decode(ssts);

    if det != SSTS_DET_PRESENT {
        // Link-down — device removed or cable unplugged.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            ahci.mmio.write32(off + PORT_IS, 0xFFFF_FFFF);
        }
        // SAFETY: same.
        unsafe { port_enable_phyrdy_irq(ahci, port_idx) };
        return PortLinkState::Disconnected;
    }

    // Link-up — run COMRESET + re-read signature.
    // SAFETY: `handle_phyrdy_change`'s contract gives exclusive HBA ownership
    // and `port_idx < 32`, matching `port_reset`'s contract.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let kind = match unsafe { ahci.port_reset(port_idx) } {
        Err(_) => {
            // SAFETY: same contract forwarded — exclusive HBA, `port_idx < 32`.
            unsafe { port_enable_phyrdy_irq(ahci, port_idx) };
            return PortLinkState::Disconnected;
        }
        Ok(()) => {
            // Read new signature from PORT_SIG / PORT_SSTS.
            // SAFETY: `off` is this port's register block (port_idx < 32, in the
            // mapped BAR); PORT_SIG is a valid in-range port register.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let sig = unsafe { ahci.mmio.read32(off + PORT_SIG) };
            // SAFETY: same port register block; PORT_SSTS is in-range.
            let ssts2 = unsafe { ahci.mmio.read32(off + PORT_SSTS) };
            PortKind::from_sig(sig, ssts2)
        }
    };

    // Re-enable PHYRDY interrupt for the next event.
    // SAFETY: identity-mapped MMIO.
    unsafe { port_enable_phyrdy_irq(ahci, port_idx) };

    PortLinkState::Connected { kind }
}

/// Which FLUSH CACHE variant a disk takes, if any (#841): EXT on
/// LBA48 devices that support it, plain FLUSH CACHE otherwise
/// (libata `ata_do_flush`). `None` = the device reports no flush
/// command at all.
fn flush_ext_choice(f: &AtaFeatures) -> Option<bool> {
    if f.flush_cache_ext && f.lba48 {
        Some(true)
    } else if f.flush_cache {
        Some(false)
    } else if f.flush_cache_ext {
        Some(true)
    } else {
        None
    }
}

/// Sync block-device adapter for the registry — ONE instance per
/// published disk (#931), addressing its own controller + port.
/// (Pre-#931 this was a unit struct that always routed to the
/// first controller's first disk port; the `from_probed`
/// constructor preserves that behaviour for compat callers.)
#[derive(Debug)]
pub struct AhciBlockSync {
    ahci: &'static Ahci,
    port: u8,
}

/// Sectors per bulk-transfer chunk: the per-controller transfer
/// buffer ([`AHCI_XFER_BYTES`]) holds exactly this many.
const XFER_SECTORS: u16 = (AHCI_XFER_BYTES / 512) as u16;

impl AhciBlockSync {
    /// The block surface for the disk on `port` of `ahci`. The
    /// port is expected to carry a published [`DiskInfo`]; the
    /// surface reports `DeviceRemoved` if it does not.
    pub fn new(ahci: &'static Ahci, port: u8) -> Self {
        Self { ahci, port }
    }

    /// The first disk of the first probed controller — the
    /// pre-#931 behaviour, kept for the smokes and compat callers
    /// that address "the" SATA disk.
    pub fn from_probed() -> Option<Self> {
        let ahci = probed_ahci()?;
        let disk = ahci.disks().into_iter().next()?;
        Some(Self {
            ahci,
            port: disk.port,
        })
    }

    /// This disk's probe-time record, if the port still carries one.
    fn disk(&self) -> Option<DiskInfo> {
        self.ahci.disk_on_port(self.port)
    }

    /// Shared entry discipline for every operation: the disk must
    /// exist and the controller must not be PM-suspended (#932).
    /// Checked again after the request gate is taken — suspend
    /// sets its flag before acquiring the gate, so a transfer that
    /// passed the first check either completes before the gate
    /// changes hands or observes the flag here.
    fn check_live(&self) -> Result<DiskInfo, narf_block::BlockIoError> {
        if self.ahci.is_suspended() {
            return Err(narf_block::BlockIoError::DeviceRemoved);
        }
        self.disk().ok_or(narf_block::BlockIoError::DeviceRemoved)
    }
}

impl narf_block::BlockDeviceSync for AhciBlockSync {
    fn lba_size(&self) -> u32 {
        512
    }
    fn capacity(&self) -> u64 {
        // Per-disk IDENTIFY capacity cached at probe (0 = unknown).
        self.disk().map(|d| d.sectors).unwrap_or(0)
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        // #930: the pre-fix `n_blocks * 512 > 4096` rejection is
        // gone — the only size contract left is the caller's own
        // buffer. Transfers chunk at the transfer buffer's size.
        if out.len() < (n_blocks as usize) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if n_blocks == 0 {
            return Ok(());
        }
        self.check_live()?;
        // Interrupts stay enabled for the whole transfer: hold the
        // device's request gate, not an IRQ-masking lock. See
        // `crate::req_gate::ReqGate`.
        let _gate = ReqGate::acquire(&self.ahci.req_gate);
        self.check_live()?;
        let stage = DmaStage {
            phys: self.ahci.xfer_phys(),
            cap: AHCI_XFER_BYTES,
        };
        let mut done: u16 = 0;
        while done < n_blocks {
            let want = XFER_SECTORS.min(n_blocks - done);
            let off = done as usize * 512;
            // SAFETY: the request gate serialises transfers,
            // scratch and transfer-buffer use on this controller.
            unsafe {
                ahci_read_lba_xfer(
                    self.ahci,
                    self.port,
                    lba + done as u64,
                    want,
                    &mut out[off..off + want as usize * 512],
                    stage,
                )
            }
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
            done += want;
        }
        Ok(())
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        if data.len() < (n_blocks as usize) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if n_blocks == 0 {
            return Ok(());
        }
        self.check_live()?;
        // Same reasoning (gate + chunking) as `read` above.
        let _gate = ReqGate::acquire(&self.ahci.req_gate);
        self.check_live()?;
        let stage = DmaStage {
            phys: self.ahci.xfer_phys(),
            cap: AHCI_XFER_BYTES,
        };
        let mut done: u16 = 0;
        while done < n_blocks {
            let want = XFER_SECTORS.min(n_blocks - done);
            let off = done as usize * 512;
            // SAFETY: the request gate serialises transfers,
            // scratch and transfer-buffer use on this controller.
            unsafe {
                ahci_write_lba_xfer(
                    self.ahci,
                    self.port,
                    lba + done as u64,
                    want,
                    &data[off..off + want as usize * 512],
                    stage,
                    false,
                )
            }
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
            done += want;
        }
        Ok(())
    }
    fn flush(&self) -> Result<(), narf_block::BlockIoError> {
        let disk = self.check_live()?;
        // A device with no flush command has no flush to issue —
        // `capabilities()` reports its cache state honestly, so Ok
        // here cannot mislead a caller about the durability of a
        // cache the device does not expose a drain for.
        let Some(ext) = flush_ext_choice(&disk.features) else {
            return Ok(());
        };
        let _gate = ReqGate::acquire(&self.ahci.req_gate);
        self.check_live()?;
        // SAFETY: the request gate serialises the port; the free
        // function's contract is the same ownership.
        unsafe { self.ahci.flush_cache(self.port, ext) }
            .map_err(|_| narf_block::BlockIoError::DriverError)
    }
    fn capabilities(&self) -> narf_block::BlockCaps {
        let features = self.disk().map(|d| d.features).unwrap_or_default();
        narf_block::BlockCaps {
            volatile_cache: features.write_cache_enabled,
            fua: features.write_fua_ext,
        }
    }
    fn write_fua(
        &self,
        lba: u64,
        n_blocks: u16,
        data: &[u8],
    ) -> Result<(), narf_block::BlockIoError> {
        let disk = self.check_live()?;
        if !disk.features.write_fua_ext {
            // Trait-default emulation, spelled out because this
            // impl overrides the method: write, then a REAL flush
            // (above) — sound precisely because flush is no longer
            // a no-op (#841).
            self.write(lba, n_blocks, data)?;
            return self.flush();
        }
        if data.len() < (n_blocks as usize) * 512 {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        if n_blocks == 0 {
            return Ok(());
        }
        let _gate = ReqGate::acquire(&self.ahci.req_gate);
        self.check_live()?;
        let stage = DmaStage {
            phys: self.ahci.xfer_phys(),
            cap: AHCI_XFER_BYTES,
        };
        let mut done: u16 = 0;
        while done < n_blocks {
            let want = XFER_SECTORS.min(n_blocks - done);
            let off = done as usize * 512;
            // SAFETY: the request gate serialises transfers,
            // scratch and transfer-buffer use on this controller.
            unsafe {
                ahci_write_lba_fua(
                    self.ahci,
                    self.port,
                    lba + done as u64,
                    want,
                    &data[off..off + want as usize * 512],
                    stage,
                )
            }
            .map_err(|_| narf_block::BlockIoError::DriverError)?;
            done += want;
        }
        Ok(())
    }
    fn supports_trim(&self) -> bool {
        self.disk().map(|d| d.features.trim).unwrap_or(false)
    }
    fn trim(&self, lba: u64, n_blocks: u64) -> Result<(), narf_block::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let disk = self.check_live()?;
        if !disk.features.trim {
            // Never silently succeed: the adapter only advertises
            // Discard when this returns true, and a direct caller
            // gets the same honesty (#841).
            return Err(narf_block::BlockIoError::DriverError);
        }
        if lba
            .checked_add(n_blocks)
            .is_none_or(|end| end > disk.sectors)
        {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let _gate = ReqGate::acquire(&self.ahci.req_gate);
        self.check_live()?;
        // Split into DSM range entries (16-bit sector counts).
        let mut ranges = alloc::vec::Vec::new();
        let mut at = lba;
        let mut left = n_blocks;
        while left > 0 {
            let c = left.min(65_535);
            ranges.push((at, c as u16));
            at += c;
            left -= c;
        }
        // SAFETY: the request gate serialises the port; the free
        // function's contract is the same ownership.
        unsafe {
            self.ahci
                .dsm_trim(self.port, &ranges, disk.features.dsm_max_blocks)
        }
        .map_err(|_| narf_block::BlockIoError::DriverError)
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Registry of the live HBAs produced by `probe` (#931: every
/// AHCI function installs, not just the first). Held only long
/// enough to read an installed device's address — NEVER across a
/// device round-trip, which busy-polls CI-clear/D2H with a
/// 30-second budget. See [`crate::req_gate`] for the livelock this
/// prevents.
///
/// Each controller is individually boxed: growing the `Vec` never
/// moves an installed `Ahci`, and entries are never removed, so
/// the `&'static Ahci` escapes below stay valid for the rest of
/// the boot. (The `Box` is the load-bearing part — clippy's
/// `vec_box` suggestion of `Vec<Ahci>` would reintroduce the
/// move-on-grow hazard.)
#[allow(clippy::vec_box)]
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<alloc::boxed::Box<Ahci>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// The first probed HBA, WITHOUT holding the registry lock for the
/// caller's use of it.
///
/// The lock is taken only long enough to read the address of the
/// installed device, then released, so a long transfer runs with
/// interrupts enabled.
///
/// # Why the reference stays valid
///
/// An installed `Ahci` is never moved, replaced or dropped:
/// [`probe`] deduplicates on the bus address, entries are appended
/// only, and each lives in its own `Box`. A shared reference to an
/// installed controller therefore stays valid for the rest of the
/// boot. `smoke_ahci_device_address_is_stable` pins that
/// invariant, because it is the kind of assumption a later
/// "support hot-unplug" change would silently invalidate. There is
/// no `&mut` path into an installed controller — every `Ahci`
/// method takes `&self`.
fn probed_ahci() -> Option<&'static Ahci> {
    let ptr: *const Ahci = {
        let g = CONTROLLERS.lock();
        match g.first() {
            Some(d) => &**d as *const Ahci,
            None => return None,
        }
    };
    // SAFETY: append-only, individually boxed, never-dropped —
    // see above.
    Some(unsafe { &*ptr })
}

/// All installed controllers, in probe order (#931).
pub fn controllers() -> alloc::vec::Vec<&'static Ahci> {
    let g = CONTROLLERS.lock();
    g.iter()
        .map(|d| {
            let ptr: *const Ahci = &**d;
            // SAFETY: same append-only/boxed invariant as
            // `probed_ahci`.
            unsafe { &*ptr }
        })
        .collect()
}

/// How many AHCI controllers are installed.
pub fn controller_count() -> usize {
    CONTROLLERS.lock().len()
}

/// Whether a controller is already installed for `addr` — the
/// probe deduplication check (#931).
fn controller_installed(addr: narf_bus::BusAddr) -> bool {
    CONTROLLERS.lock().iter().any(|c| c.addr == addr)
}

/// Append a fully-initialised controller to the registry and
/// return its installed reference.
fn install_controller(dev: Ahci) -> &'static Ahci {
    let mut g = CONTROLLERS.lock();
    g.push(alloc::boxed::Box::new(dev));
    let ptr: *const Ahci = &**g.last().expect("just pushed");
    // SAFETY: same append-only/boxed invariant as `probed_ahci`.
    unsafe { &*ptr }
}

/// The first installed HBA's address, or `None` before probe.
/// Test hook for the install-stability invariant `probed_ahci`
/// relies on.
#[doc(hidden)]
pub fn dbg_device_addr() -> Option<usize> {
    CONTROLLERS
        .lock()
        .first()
        .map(|d| &**d as *const Ahci as usize)
}

/// IDT vector our ISR is installed on, or 0 if no IRQ path was
/// successfully negotiated. Loaded by both ISR and async waiters.
/// Stays at 0 until `try_setup_irq` succeeds.
static AHCI_IRQ_VECTOR: AtomicU8 = AtomicU8::new(0);

/// MMIO base for the registered HBA. Stored as `usize` so the ISR
/// can reach it without locking (the ISR runs in IRQ context where
/// taking `IrqSafeSpinLock` would deadlock if the lock was already
/// held by the path that triggered the IRQ).
/// The ABAR's mapped kernel VA (not its physical address): the ISR
/// dereferences it with no further translation step.
static AHCI_MMIO_BASE: AtomicUsize = AtomicUsize::new(0);

/// MSI-X table backing — kept alive for the life of the controller
/// so its physical pages aren't reclaimed underneath us.
static AHCI_MSIX: IrqSafeSpinLock<Option<MsixTable>> = IrqSafeSpinLock::new(None);

/// Synchronous AHCI ISR. Called by `narf_interrupts::dispatch::on_irq`
/// before the per-vector `fire_count` increment + waker fan-out. Job:
/// drain the level-triggered IRQ source so the next event is allowed
/// to fire.
///
/// Bounded work: HBA `IS` is a 32-bit per-port bitmap, so at worst
/// we walk 32 ports per fire (AHCI 1.3.1 §3.1.3). Each port's
/// `PORT_IS` is also a fixed 32-bit register. No unbounded loops.
fn ahci_isr() {
    let base = AHCI_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    // SAFETY: `base` is the ABAR's mapped kernel VA, stashed
    // post-bring-up and owned by the AHCI driver.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let is = unsafe { core::ptr::read_volatile((base as u64 + HBA_IS) as *const u32) };
    if is == 0 {
        return;
    }
    // Clear each port's per-port IS first (W1C inside the port,
    // §3.3.5), then clear the HBA-wide IS bit (W1C, §3.1.3). Order
    // matters: per spec the HBA IS bit only re-asserts if PORT_IS
    // is non-zero after the host clears it, so draining PORT_IS
    // first prevents an immediate re-fire.
    for n in 0..32u8 {
        let bit = 1u32 << n;
        if is & bit == 0 {
            continue;
        }
        let off = PORT_BASE_OFF + (n as u64) * PORT_STRIDE;
        // SAFETY: same identity-mapped MMIO window.
        let pis = unsafe { core::ptr::read_volatile((base as u64 + off + PORT_IS) as *mut u32) };
        if pis != 0 {
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile((base as u64 + off + PORT_IS) as *mut u32, pis);
            }
        }
    }
    // SAFETY: same.
    unsafe {
        core::ptr::write_volatile((base as u64 + HBA_IS) as *mut u32, is);
    }
}

/// Try to bring up MSI-X for the AHCI controller. Mirrors
/// `Xhci::try_enable_msix` — walks the cap, allocates an IDT vector,
/// programs MSI-X table entry 0 to deliver to the BSP, then flips
/// the global enable. Returns `(table, vector)` on success.
fn try_enable_msix_ahci(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Option<(MsixTable, u8)> {
    let mut msix = enable_msix(cap, device).ok()?;
    let v = narf_interrupts::vector::alloc().ok()?;
    let _ = msix.alloc_vector()?;
    // SAFETY: we hold the BusDeviceCap and own the MSI-X table; the
    // vector + handler are installed by the caller before enable().
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { msix.program_vector(0, 0, v) }.ok()?;
    // SAFETY: cfg-space write to a known cap-list offset.
    unsafe { msix.enable() }.ok()?;
    Some((msix, v))
}

/// Try MSI (single-vector) as a middle fallback between MSI-X and
/// legacy INTx. Some emulated AHCI controllers expose the MSI cap
/// but not MSI-X.
#[cfg(target_arch = "x86_64")]
fn try_enable_msi_ahci(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Option<u8> {
    let mut cfg = narf_bus::msi::enable_msi(cap, device, 1).ok()?;
    let v = narf_interrupts::vector::alloc().ok()?;
    // SAFETY: caller-authority over cfg space; vector reserved.
    let _ = unsafe { narf_bus::msi::program_msi(&mut cfg, 0, v) }.ok()?;
    // SAFETY: same.
    unsafe { narf_bus::msi::enable(&cfg) }.ok()?;
    Some(v)
}
#[cfg(not(target_arch = "x86_64"))]
fn try_enable_msi_ahci(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
    None
}

/// Legacy INTx fallback. Walks PCI INTERRUPT_PIN, looks the line up
/// in the AML `_PRT`, allocates an IDT vector, and routes the GSI
/// through the IOAPIC level/active-low.
#[cfg(target_arch = "x86_64")]
fn try_install_intx_ahci(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Option<u8> {
    let pin = narf_bus::pci::read_intx_pin(cap, device).ok()?;
    if pin == 0 || pin > 4 {
        return None;
    }
    let slot = match device.kind {
        narf_bus::BusKind::Pcie { addr, .. } => addr.device,
        _ => return None,
    };
    let prt_pin = pin - 1;
    let route = narf_aml::irq_routing::route_for("\\_SB.PCI0", slot, prt_pin)?;
    if route.entry.source.is_some() {
        return None;
    }
    let gsi = route.entry.source_index;
    let v = narf_interrupts::vector::alloc().ok()?;
    // Handler is installed by the caller before this routes the GSI,
    // so the first delivered IRQ already has the AHCI ISR registered.
    // SAFETY: vector + handler set above before the route.
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
fn try_install_intx_ahci(_cap: &Cap<BusDeviceCap, Write>, _device: &BusDevice) -> Option<u8> {
    None
}

/// Negotiate an IRQ delivery path (MSI-X → MSI → INTx). On success,
/// installs `ahci_isr` on the chosen vector + records the vector in
/// `AHCI_IRQ_VECTOR`. On total failure leaves `AHCI_IRQ_VECTOR` at
/// 0 — async paths will fall back to sync polling.
fn try_setup_irq(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) {
    if let Some((tbl, v)) = try_enable_msix_ahci(cap, device) {
        narf_interrupts::install_handler(v, ahci_isr);
        *AHCI_MSIX.lock() = Some(tbl);
        AHCI_IRQ_VECTOR.store(v, Ordering::Release);
        return;
    }
    if let Some(v) = try_enable_msi_ahci(cap, device) {
        narf_interrupts::install_handler(v, ahci_isr);
        AHCI_IRQ_VECTOR.store(v, Ordering::Release);
        return;
    }
    if let Some(v) = try_install_intx_ahci(cap, device) {
        narf_interrupts::install_handler(v, ahci_isr);
        AHCI_IRQ_VECTOR.store(v, Ordering::Release);
    }
}

// ── Device power management (#932) ──────────────────────────────
//
// AHCI joins the `narf_power::device_pm` fan-out like NVMe (PR
// #966): the handlers below run on the boot CPU with interrupts
// gated and must not schedule. Every wait on this path is a polled
// register wait (`responsive_spin_until`) and the request gate
// spins without masking interrupts, so the context is safe. The
// fan-out calls handlers in reverse registration order on suspend
// and forward order on resume; AHCI registers once under the name
// "ahci" (registration is idempotent on the name).

/// Suspend every installed controller. A controller whose disks
/// cannot be flushed + idled reports `Busy`, which aborts the
/// system suspend — the machine stays awake rather than powering
/// down over an unflushed write cache (PR #966's NVMe contract).
fn ahci_suspend_all() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let mut failed = false;
    for ctrl in controllers() {
        if ahci_suspend_controller(ctrl).is_err() {
            failed = true;
        }
    }
    if failed {
        Err(narf_power::device_pm::DeviceSuspendError::Busy)
    } else {
        Ok(())
    }
}

fn ahci_suspend_controller(ctrl: &Ahci) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    // Refuse new I/O first. The block surface checks this flag on
    // entry, so a transfer already past its check holds the
    // request gate we are about to take (and completes before we
    // proceed); everything later fails fast with DeviceRemoved.
    ctrl.suspended.store(true, Ordering::Release);
    let _gate = ReqGate::acquire(&ctrl.req_gate);
    let mut result = Ok(());
    for disk in ctrl.disks() {
        // Drain the volatile write cache BEFORE idling the port.
        if let Some(ext) = flush_ext_choice(&disk.features) {
            // SAFETY: the request gate is held; the port carries a
            // published disk.
            if unsafe { ctrl.flush_cache(disk.port, ext) }.is_err() {
                result = Err(DeviceSuspendError::Busy);
            }
        }
        // SAFETY: same ownership.
        let _ = unsafe { ctrl.port_idle(disk.port) };
    }
    result
}

/// Resume every installed controller. A controller whose disks do
/// not revalidate stays suspended (its block surface keeps
/// refusing I/O) and reports `DriverError`.
fn ahci_resume_all() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let mut failed = false;
    for ctrl in controllers() {
        if ahci_resume_controller(ctrl).is_err() {
            failed = true;
        }
    }
    if failed {
        Err(narf_power::device_pm::DeviceSuspendError::DriverError)
    } else {
        Ok(())
    }
}

fn ahci_resume_controller(ctrl: &Ahci) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let _gate = ReqGate::acquire(&ctrl.req_gate);
    // Re-run the probe init sequence against the SAME mapped BAR
    // and the SAME init DMA areas (the mapping and the areas
    // survive suspend; only device state was lost). The BIOS
    // handoff inside `hba_global_init` is a no-op here — ownership
    // is already with the OS.
    let init = ctrl
        ._init_dma
        .as_ref()
        .map(|b| (b.dma_addr().raw(), b.dma_addr_at(INIT_FIS_BASE).raw()));
    let cfg = hba_global_init(&Abar(&ctrl.mmio)).map_err(|_| DeviceSuspendError::DriverError)?;
    let ports = bring_up_ports(
        &Abar(&ctrl.mmio),
        cfg.cap,
        cfg.port_map,
        init,
        HBA_PORT_BRINGUP_BUDGET_MS,
    );
    hba_finish_init(&Abar(&ctrl.mmio));
    if ctrl.irq_vector != 0 {
        hba_enable_irq(&Abar(&ctrl.mmio));
    }
    // Revalidate every published disk before trusting it again:
    // after resume the device behind a port must be the device
    // that was there before — same class, same capacity, same
    // model. Anything else means the medium changed under a
    // suspended system; keep the controller suspended and fail
    // rather than serve a stranger's disk under the old name.
    // (`Ahci::ports` keeps the probe-time classification; the
    // `disks` table is the live one the block surface reads.)
    let mut fresh = alloc::vec::Vec::new();
    for disk in ctrl.disks() {
        let kind = ports.iter().find(|p| p.index == disk.port).map(|p| p.kind);
        if kind != Some(PortKind::Sata) {
            return Err(DeviceSuspendError::DriverError);
        }
        // SAFETY: the request gate is held; we own the HBA inside
        // the PM handler and the port classified as an ATA disk.
        let id = unsafe { ctrl.identify_device(disk.port) }
            .map_err(|_| DeviceSuspendError::DriverError)?;
        let sectors = identify_n_sectors(&id);
        let model = identify_model_string(&id);
        if sectors != disk.sectors || model != disk.model {
            return Err(DeviceSuspendError::DriverError);
        }
        fresh.push(DiskInfo {
            port: disk.port,
            sectors,
            features: identify_ata_features(&id),
            model,
            serial: identify_serial(&id),
            firmware: identify_firmware(&id),
        });
    }
    ctrl.set_disks(fresh);
    ctrl.suspended.store(false, Ordering::Release);
    Ok(())
}

/// Next `sata<n>` registry name. Names are never reused within a
/// boot: hot-removed disks are out of scope, and reuse would alias
/// a new disk onto a name a filesystem may still hold open.
fn next_sata_name() -> &'static str {
    static NEXT_SATA: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT_SATA.fetch_add(1, Ordering::Relaxed);
    alloc::boxed::Box::leak(alloc::format!("sata{n}").into_boxed_str())
}

/// `0000:00:1f.2`-style bus path for a controller's
/// `DiskIdentity` (empty for non-PCIe addresses).
fn bus_path_of(addr: narf_bus::BusAddr) -> alloc::string::String {
    match addr {
        narf_bus::BusAddr::Pcie(a) => {
            alloc::format!(
                "{:04x}:{:02x}:{:02x}.{}",
                a.segment,
                a.bus,
                a.device,
                a.function
            )
        }
        _ => alloc::string::String::new(),
    }
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    // #931: a repeat probe of an already-installed function is a
    // no-op — re-running bring-up would reset a live controller,
    // and the install-stability invariant forbids replacing it. A
    // DIFFERENT function installs alongside the existing ones.
    if controller_installed(device.addr) {
        return Ok(());
    }
    let first = controller_count() == 0;
    // Enable MEM_SPACE + BUS_MASTER. We leave INTX_DISABLE clear so
    // that the legacy INTx fallback is reachable; if MSI / MSI-X
    // negotiation succeeds, the device's INTx pin is still inert
    // because no per-port IS bit will translate into an INTx
    // assertion under the device's MSI-mode behaviour (PCIe spec
    // §6.8: MSI/MSI-X enable in cfg-space suppresses INTx).
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority over the device's BAR.
    let mut dev = match unsafe { Ahci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // IDENTIFY every ATA-disk port (#931): each becomes a
    // published disk with its own capacity, feature set and
    // identity. A port whose IDENTIFY fails is not published —
    // same reasoning as the pre-#931 no-disk case below: a phantom
    // disk's every read would wait out command timeouts, and root
    // designation (which reads every device's UUID) would stall
    // on it. IDENTIFY only reads.
    let mut disks = alloc::vec::Vec::new();
    for p in dev.ports.iter().filter(|p| p.kind == PortKind::Sata) {
        // SAFETY: the HBA is not installed yet, so we own it; the
        // port classified as an ATA disk.
        if let Ok(id) = unsafe { dev.identify_device(p.index) } {
            disks.push(DiskInfo {
                port: p.index,
                sectors: identify_n_sectors(&id),
                features: identify_ata_features(&id),
                model: identify_model_string(&id),
                serial: identify_serial(&id),
                firmware: identify_firmware(&id),
            });
        }
    }
    // Compat first-disk fields (`capacity()`'s pre-#931 source and
    // smokes read them): block_port falls back to port 0 when no
    // port published a disk.
    if let Some(first_disk) = disks.first() {
        dev.block_port = first_disk.port;
        dev.capacity = first_disk.sectors;
    }
    dev.set_disks(disks);
    if first {
        // The shared ISR (`ahci_isr` + the `AHCI_MMIO_BASE` /
        // `AHCI_IRQ_VECTOR` globals) is a single-controller
        // design, so only the FIRST installed HBA negotiates an
        // IRQ. Later HBAs poll: their async completion waits take
        // the `irq_vector == 0` deadline path (correct, just not
        // interrupt-driven). Lifting this means per-controller ISR
        // state — a follow-up, not silently half-done here.
        //
        // Stash the MMIO base for the ISR before any IRQ can fire.
        // The ISR dereferences this directly, so stash the mapped
        // VA, not the BAR's physical address — `MmioRegion::virt`
        // is the ioremap window for above-map BARs and equals the
        // PA only for identity-mapped ones.
        AHCI_MMIO_BASE.store(dev.mmio.virt as usize, Ordering::Release);
        // Negotiate IRQ delivery (MSI-X → MSI → INTx). Best-effort —
        // failure leaves the driver in sync-poll mode.
        try_setup_irq(&cap, &device);
        dev.irq_vector = AHCI_IRQ_VECTOR.load(Ordering::Acquire);
        // Only now may the HBA interrupt: the ISR is installed and
        // the vector routed. Without a route GHC.IE stays clear
        // and the driver polls.
        if dev.irq_vector != 0 {
            hba_enable_irq(&Abar(&dev.mmio));
        }
    }
    let ctrl = install_controller(dev);
    // #932: join the device_pm suspend/resume fan-out (idempotent
    // on the name, so later HBAs re-register the same handlers).
    narf_power::device_pm::register_device_pm("ahci", ahci_suspend_all, ahci_resume_all);
    // An HBA with no ATA disk behind it (QEMU q35's built-in ICH9
    // with no `-drive` on it, a laptop chipset SATA controller with
    // empty ports) publishes nothing. Linux's libata likewise
    // creates no `ata_device` (so no `sd`) for a port whose link
    // is down.
    let disks = ctrl.disks();
    if disks.is_empty() {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  ahci: no ATA disk on any port; not registering any sata disk"
        );
        return Ok(());
    }
    // Publish every disk against the unified block-device
    // registry, each with its hardware identity (#931), its
    // partition scan, and its bound-driver record — as the NVMe,
    // virtio-blk and USB drivers do per device.
    let bus_path = bus_path_of(device.addr);
    for disk in &disks {
        let name = next_sata_name();
        let surface = alloc::sync::Arc::new(AhciBlockSync::new(ctrl, disk.port))
            as alloc::sync::Arc<dyn narf_block::BlockDeviceSync>;
        narf_block::register_block_device_with_identity(
            name,
            surface.clone(),
            narf_block::DiskIdentity {
                transport: "ata",
                bus_path: bus_path.clone(),
                controller: alloc::string::String::from(name),
                model: disk.model.clone(),
                serial: disk.serial.clone(),
                firmware: disk.firmware.clone(),
                vendor_id: device.id.vendor,
                nsid: 0,
                // NVMe-namespace identifiers; ATA has no
                // equivalents in this identity shape.
                eui64: None,
                nguid: None,
                uuid: None,
            },
        );
        // Register `<name>p<n>` for each MBR / GPT partition.
        // Reads only; an unpartitioned disk just keeps the
        // whole-disk entry. Every partition goes through the
        // registry's `PolicyGuard` like its parent.
        let _ = narf_block::partition::scan_and_register_partitions(surface, name);
        narf_drivers::record_bound(narf_drivers::BoundDriver {
            name: alloc::string::String::from(name),
            kind: narf_drivers::BoundKind::Block,
            pci_vid: Some(device.id.vendor),
            pci_did: Some(device.id.device),
            domain: narf_drivers::BoundKind::Block.default_domain(),
        });
    }
    Ok(())
}

/// Register the AHCI driver with the bus match table.
///
/// - Explicit `(vendor, device)` entries for the Intel ICH9 (QEMU q35)
///   and ICH10 controllers.
/// - The generic class entry Linux's `ahci_pci_tbl` ends with
///   (`PCI_CLASS_STORAGE_SATA_AHCI`, `board_ahci`): any `01:06:01`
///   controller, e.g. the AMD 600-series chipset `1022:43f6`. Linux has
///   no per-ID quirk for that controller family (see
///   [`AMD_600_SERIES_SATA_DEV`]), so the generic path is the Linux path.
///
/// Not mirrored: Linux's AMD entry for RAID-class (`01:04`) controllers
/// in AHCI mode — the match table cannot express vendor + class, and a
/// RAID-mode BIOS setting is not the configuration NARF targets.
pub fn register_pci_driver() {
    for did in [AHCI_ICH9_DEV, AHCI_ICH10_DEV] {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: AHCI_VENDOR,
                device: did,
            },
            probe,
        });
    }
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "ahci-class",
        kind: narf_bus::MatchKind::ClassFull {
            class: PCI_CLASS_STORAGE,
            subclass: PCI_SUBCLASS_SATA,
            prog_if: PCI_PROGIF_AHCI,
        },
        probe,
    });
}

fn name_for(did: u16) -> &'static str {
    match did {
        AHCI_ICH9_DEV => "ahci-ich9",
        AHCI_ICH10_DEV => "ahci-ich10",
        _ => "ahci",
    }
}

pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// Run `f` against the probed HBA, if any.
///
/// Holds the device's request gate — not the registry spinlock —
/// for the duration of `f`, so closures that do polled I/O
/// (`identify_device`, `ahci_read_lba`, ...) wait out the transfer
/// with interrupts enabled while still excluding every other user of
/// the HBA and its shared scratch. Callers must not re-enter
/// `with_controller` (or the `AhciBlockSync` paths) from inside `f` —
/// the gate is not reentrant.
pub fn with_controller<R>(f: impl FnOnce(&Ahci) -> R) -> Option<R> {
    let ahci = probed_ahci()?;
    let _gate = ReqGate::acquire(&ahci.req_gate);
    Some(f(ahci))
}

#[allow(dead_code)]
fn unused_silencer(mmio: &MmioRegion) {
    // Force compiler to keep compiler_fence import alive in low-cfg
    // builds.
    let _ = mmio;
    compiler_fence(Ordering::SeqCst);
}
