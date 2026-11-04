//! AMD-Vi (AMD I/O Virtualization Technology) silicon backend for
//! [`crate::iommu::IommuHw`].
//!
//! Mirrors Linux `drivers/iommu/amd/{init.c,iommu.c,amd_iommu_types.h}`
//! (7.3-rc4) for the subset NARF needs: v1 host page tables with
//! per-device default domains, no interrupt remapping, no ATS, no PPR /
//! guest translation / SNP.
//!
//! Bring-up ([`bring_up`], Linux `early_enable_iommu`, one PCI segment):
//! 1. IVRS → units, requester-ID lookup, aliases, IVHD DTE setting flags,
//!    IVMD unity ranges ([`ivrs`]).
//! 2. One 2 MiB device table (65 536 × 256-bit DTEs, naturally aligned
//!    order-9 block) shared by every unit of segment 0. Every DTE starts as
//!    Linux's identity (`iommu=pt`) entry, `set_dte_passthrough`:
//!    `V | TV | IR | IW`, `Mode = 0`, domain 0 — so a device nobody
//!    attaches keeps untranslated DMA exactly as with the IOMMU off.
//! 3. Per unit: `iommu_disable` → `iommu_init_flags` (HT tunnel /
//!    PassPW / ResPassPW / Isoc from the IVHD flags, `Coherent`, 1 s
//!    invalidation timeout) → `iommu_set_device_table` →
//!    `iommu_enable_command_buffer` (512 entries) → `IommuEn` →
//!    `amd_iommu_flush_all_caches` → `iommu_enable_event_buffer`
//!    (512 entries).
//!
//! Not enabled, on purpose: interrupt remapping (`IntCtl` / `IV` stay 0,
//! so MSIs and IOAPIC/HPET interrupts pass through untranslated; no IRT,
//! `GAEn`, `XTEn`, 2K-IRTE mode or `INVALIDATE_INTERRUPT_TABLE`), ATS
//! (`DTE.I = 0`, so `INVALIDATE_IOTLB_PAGES` is never needed), PPR / EPH,
//! guest translation, the event-log interrupt (the log is polled after
//! every completion wait and by [`poll_events`]). Linux's AMD-Vi errata
//! workarounds in `init.c` target family 15h (746, ATS write check) or
//! SNP systems; none applies to family 17h (Renoir) / 19h (Phoenix)
//! without SNP. Erratum 63 (SysMgt = 01b ⇒ `IW`) and the 732 event-log
//! race are handled as Linux does. SME is not used by NARF, so page-table
//! pointers carry no C-bit.

extern crate alloc;

pub mod ivrs;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, fence, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::iommu::{Bdf, DirectMapping, IommuHw, IommuPerms, PageTableFormat};
use crate::IoError;

use ivrs::{IvhdUnit, IvrsInfo, UnityRange};

// ── MMIO register block (Linux `MMIO_*_OFFSET`) ────────────────────
pub const MMIO_DEV_TABLE: u64 = 0x0000;
pub const MMIO_CMD_BUF: u64 = 0x0008;
pub const MMIO_EVT_BUF: u64 = 0x0010;
pub const MMIO_CONTROL: u64 = 0x0018;
pub const MMIO_EXT_FEATURES: u64 = 0x0030;
pub const MMIO_CMD_HEAD: u64 = 0x2000;
pub const MMIO_CMD_TAIL: u64 = 0x2008;
pub const MMIO_EVT_HEAD: u64 = 0x2010;
pub const MMIO_EVT_TAIL: u64 = 0x2018;
pub const MMIO_STATUS: u64 = 0x2020;
/// Bytes mapped per unit (covers the head/tail/status page).
pub const MMIO_REGION_LEN: u64 = 0x4000;

pub const MMIO_STATUS_EVT_OVERFLOW: u64 = 1 << 0;
pub const MMIO_STATUS_EVT_RUN: u64 = 1 << 3;

// ── Control register bits (Linux `CONTROL_*`) ──────────────────────
pub const CONTROL_IOMMU_EN: u32 = 0;
pub const CONTROL_HT_TUN_EN: u32 = 1;
pub const CONTROL_EVT_LOG_EN: u32 = 2;
pub const CONTROL_EVT_INT_EN: u32 = 3;
pub const CONTROL_INV_TIMEOUT: u32 = 5;
pub const CONTROL_PASSPW_EN: u32 = 8;
pub const CONTROL_RESPASSPW_EN: u32 = 9;
pub const CONTROL_COHERENT_EN: u32 = 10;
pub const CONTROL_ISOC_EN: u32 = 11;
pub const CONTROL_CMDBUF_EN: u32 = 12;
pub const CONTROL_PPRLOG_EN: u32 = 13;
pub const CONTROL_PPRINT_EN: u32 = 14;
pub const CONTROL_GALOG_EN: u32 = 28;
pub const CONTROL_GAINT_EN: u32 = 29;
pub const CONTROL_IRTCACHEDIS: u32 = 59;
pub const CTRL_INV_TO_MASK: u64 = 7;
pub const CTRL_INV_TO_1S: u64 = 4;

/// EFR bit 6: `INVALIDATE_IOMMU_ALL` supported (Linux `FEATURE_IA`).
pub const FEATURE_IA: u64 = 1 << 6;
/// EFR bits 11:10: host address translation size (Linux `FEATURE_HATS`;
/// max levels = HATS + 4, 3 = reserved).
pub const FEATURE_HATS_SHIFT: u32 = 10;

// ── Rings ──────────────────────────────────────────────────────────
pub const CMD_BUFFER_SIZE: u32 = 8192;
pub const CMD_ENTRY_SIZE: u32 = 16;
pub const MMIO_CMD_SIZE_512: u64 = 0x9 << 56;
pub const EVTLOG_SIZE: u32 = 8192;
pub const EVTLOG_ENTRY_SIZE: u32 = 16;
pub const EVTLOG_LEN_MASK_DEF: u64 = 0x9 << 56;

// ── Commands (Linux `CMD_*`) ───────────────────────────────────────
pub const CMD_COMPL_WAIT: u32 = 0x01;
pub const CMD_INV_DEV_ENTRY: u32 = 0x02;
pub const CMD_INV_IOMMU_PAGES: u32 = 0x03;
pub const CMD_INV_ALL: u32 = 0x08;
pub const CMD_COMPL_WAIT_STORE: u32 = 0x01;
pub const CMD_INV_IOMMU_PAGES_SIZE: u64 = 0x01;
pub const CMD_INV_IOMMU_PAGES_PDE: u64 = 0x02;
pub const CMD_INV_IOMMU_ALL_PAGES_ADDRESS: u64 = 0x7fff_ffff_ffff_f000;

// ── Device table (Linux `DTE_*`, `DEV_ENTRY_*`) ────────────────────
pub const DEV_TABLE_ENTRIES: usize = 0x1_0000;
pub const DTE_SIZE: usize = 32;
/// 2 MiB = buddy order 9 (naturally aligned, so the 4 KiB base alignment
/// and the size-field encoding both hold).
pub const DEV_TABLE_ORDER: u8 = 9;
pub const DTE_FLAG_V: u64 = 1 << 0;
pub const DTE_FLAG_TV: u64 = 1 << 1;
pub const DTE_MODE_SHIFT: u32 = 9;
pub const DTE_MODE_MASK: u64 = 0x7 << DTE_MODE_SHIFT;
pub const DTE_HOST_TRP: u64 = 0x000F_FFFF_FFFF_F000;
pub const DTE_FLAG_IR: u64 = 1 << 61;
pub const DTE_FLAG_IW: u64 = 1 << 62;
pub const DTE_DOMID_MASK: u64 = 0xffff;
pub const DEV_ENTRY_SYSMGT1: u32 = 0x68;
pub const DEV_ENTRY_SYSMGT2: u32 = 0x69;
pub const DEV_ENTRY_INIT_PASS: u32 = 0xb8;
pub const DEV_ENTRY_EINT_PASS: u32 = 0xb9;
pub const DEV_ENTRY_NMI_PASS: u32 = 0xba;
pub const DEV_ENTRY_LINT0_PASS: u32 = 0xbe;
pub const DEV_ENTRY_LINT1_PASS: u32 = 0xbf;

// ── Event log (Linux `EVENT_*`) ────────────────────────────────────
pub const EVENT_TYPE_ILL_DEV: u8 = 0x1;
pub const EVENT_TYPE_IO_FAULT: u8 = 0x2;
pub const EVENT_TYPE_DEV_TAB_ERR: u8 = 0x3;
pub const EVENT_TYPE_PAGE_TAB_ERR: u8 = 0x4;
pub const EVENT_TYPE_ILL_CMD: u8 = 0x5;
pub const EVENT_TYPE_CMD_HARD_ERR: u8 = 0x6;
pub const EVENT_TYPE_IOTLB_INV_TO: u8 = 0x7;
pub const EVENT_TYPE_INV_DEV_REQ: u8 = 0x8;

/// Completion-wait / queue-space bound: Linux `LOOP_TIMEOUT` × `udelay(1)`.
pub const WAIT_TIMEOUT_NS: u64 = 100_000_000;
/// Largest IVMD unity range mapped into a domain (4 KiB leaves).
pub const MAX_DIRECT_MAP_BYTES: u64 = 1 << 30;

/// One 128-bit command (`struct iommu_cmd`).
pub type Cmd = [u32; 4];
/// One 256-bit device table entry (`struct dev_table_entry`).
pub type Dte = [u64; 4];

#[inline]
fn set_type(cmd: &mut Cmd, ty: u32) {
    cmd[1] |= ty << 28;
}

/// Linux `build_completion_wait`: store `data` to `sem_phys` (8-byte
/// aligned) once every earlier command has completed.
pub fn cmd_completion_wait(sem_phys: u64, data: u64) -> Cmd {
    let mut c = [
        (sem_phys as u32) | CMD_COMPL_WAIT_STORE,
        (sem_phys >> 32) as u32,
        data as u32,
        (data >> 32) as u32,
    ];
    set_type(&mut c, CMD_COMPL_WAIT);
    c
}

/// Linux `build_inv_dte`.
pub fn cmd_inv_dte(devid: u16) -> Cmd {
    let mut c = [devid as u32, 0, 0, 0];
    set_type(&mut c, CMD_INV_DEV_ENTRY);
    c
}

/// Linux `build_inv_address`: the smallest naturally aligned power-of-two
/// range covering `[address, last]` in the S-bit size encoding.
pub fn build_inv_address(address: u64, last: u64) -> u64 {
    let address = address & !0xfff;
    let x = address ^ last;
    let sz_lg2 = 64 - x.leading_zeros();
    if sz_lg2 <= 12 {
        return address;
    }
    if sz_lg2 > 52 {
        return CMD_INV_IOMMU_ALL_PAGES_ADDRESS | CMD_INV_IOMMU_PAGES_SIZE;
    }
    let mut a = address;
    if sz_lg2 > 13 {
        // GENMASK(sz_lg2 - 2, 12)
        a |= ((1u64 << (sz_lg2 - 1)) - 1) & !0xfff;
    }
    a | CMD_INV_IOMMU_PAGES_SIZE
}

/// Linux `build_inv_iommu_pages` without PASID, `PDE` set ("flush
/// everything, not only the PTEs"). `last` is inclusive.
pub fn cmd_inv_iommu_pages(domid: u16, address: u64, last: u64) -> Cmd {
    let inv = build_inv_address(address, last) | CMD_INV_IOMMU_PAGES_PDE;
    let mut c = [0, domid as u32, inv as u32, (inv >> 32) as u32];
    set_type(&mut c, CMD_INV_IOMMU_PAGES);
    c
}

/// Linux `build_inv_all` (`INVALIDATE_IOMMU_ALL`, needs `FEATURE_IA`).
pub fn cmd_inv_all() -> Cmd {
    let mut c = [0; 4];
    set_type(&mut c, CMD_INV_ALL);
    c
}

#[inline]
fn set_dte_bit(d: &mut Dte, bit: u32) {
    d[(bit / 64) as usize] |= 1u64 << (bit % 64);
}

/// Linux `set_dev_entry_from_acpi_range`: persistent DTE bits from an
/// IVHD device entry's setting flags, including erratum 63.
pub fn dte_initial(flags: u8) -> Dte {
    use ivrs::*;
    let mut d = [0u64; 4];
    for (f, bit) in [
        (ACPI_DEVFLAG_INITPASS, DEV_ENTRY_INIT_PASS),
        (ACPI_DEVFLAG_EXTINT, DEV_ENTRY_EINT_PASS),
        (ACPI_DEVFLAG_NMI, DEV_ENTRY_NMI_PASS),
        (ACPI_DEVFLAG_SYSMGT1, DEV_ENTRY_SYSMGT1),
        (ACPI_DEVFLAG_SYSMGT2, DEV_ENTRY_SYSMGT2),
        (ACPI_DEVFLAG_LINT0, DEV_ENTRY_LINT0_PASS),
        (ACPI_DEVFLAG_LINT1, DEV_ENTRY_LINT1_PASS),
    ] {
        if flags & f != 0 {
            set_dte_bit(&mut d, bit);
        }
    }
    if (d[1] >> 40) & 0x3 == 0x1 {
        d[0] |= DTE_FLAG_IW;
    }
    d
}

/// Linux identity domain (`set_dte_passthrough`): DMA passes untranslated.
pub fn dte_passthrough(initial: Dte) -> Dte {
    let mut d = initial;
    d[0] |= DTE_FLAG_V | DTE_FLAG_TV | DTE_FLAG_IR | DTE_FLAG_IW;
    d
}

/// Blocking entry: valid, translation valid, `Mode = 0`, no `IR`/`IW` —
/// the DTE Linux `init_device_table_dma` gives every device (erratum-63
/// `IW` survives, as Linux's `amd_iommu_make_clear_dte` keeps it).
pub fn dte_blocked(initial: Dte) -> Dte {
    let mut d = initial;
    d[0] |= DTE_FLAG_V | DTE_FLAG_TV;
    d
}

/// Linux `amd_iommu_set_dte_v1`: `TV`, `Mode = levels`, host page-table
/// root, `IR | IW`, domain ID (no dirty tracking, no ATS).
pub fn dte_translated(initial: Dte, root: u64, levels: u8, domid: u16) -> Dte {
    let mut d = initial;
    d[0] |= DTE_FLAG_V
        | DTE_FLAG_TV
        | (((levels as u64) << DTE_MODE_SHIFT) & DTE_MODE_MASK)
        | (root & DTE_HOST_TRP)
        | DTE_FLAG_IR
        | DTE_FLAG_IW;
    d[1] |= domid as u64 & DTE_DOMID_MASK;
    d
}

// ── Register access ────────────────────────────────────────────────

/// One unit's register block. [`MmioRegs`] on hardware; tests supply a
/// register model.
pub trait AmdViRegs: Send + Sync {
    fn read64(&self, off: u64) -> u64;
    fn write64(&self, off: u64, val: u64);
    fn read32(&self, off: u64) -> u32;
    fn write32(&self, off: u64, val: u32);
}

/// `ioremap`ped AMD-Vi register block.
#[derive(Debug)]
pub struct MmioRegs {
    va: u64,
}

impl MmioRegs {
    /// Map `MMIO_REGION_LEN` bytes at `phys` (Linux `iommu_map_mmio_space`).
    ///
    /// # Safety
    /// `phys` must be an AMD-Vi register block reported by the IVRS.
    pub unsafe fn map(phys: u64) -> Option<Self> {
        if phys == 0 || phys & 0xfff != 0 {
            return None;
        }
        // SAFETY: caller contract — IVRS-reported device MMIO, mapped
        // uncached through the kernel device-mapping facility.
        let m = unsafe {
            narf_memory::ioremap::ioremap(
                phys,
                MMIO_REGION_LEN,
                narf_memory::ioremap::MmioAttrs::Device,
            )
        }
        .ok()?;
        Some(Self { va: m.va() })
    }
}

// Invariant #4: every MMIO access is fenced on both sides so fat LTO
// cannot move ring / DTE stores across the doorbell write.
impl AmdViRegs for MmioRegs {
    fn read64(&self, off: u64) -> u64 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: `off + 8 <= MMIO_REGION_LEN` for every register used;
        // the mapping lives forever.
        let v = unsafe { core::ptr::read_volatile((self.va + off) as *const u64) };
        compiler_fence(Ordering::SeqCst);
        v
    }
    fn write64(&self, off: u64, val: u64) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: as `read64`.
        unsafe { core::ptr::write_volatile((self.va + off) as *mut u64, val) };
        compiler_fence(Ordering::SeqCst);
    }
    fn read32(&self, off: u64) -> u32 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: as `read64`.
        let v = unsafe { core::ptr::read_volatile((self.va + off) as *const u32) };
        compiler_fence(Ordering::SeqCst);
        v
    }
    fn write32(&self, off: u64, val: u32) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: as `read64`.
        unsafe { core::ptr::write_volatile((self.va + off) as *mut u32, val) };
        compiler_fence(Ordering::SeqCst);
    }
}

fn feature_set(r: &dyn AmdViRegs, bit: u32, on: bool) {
    let c = r.read64(MMIO_CONTROL);
    let n = if on { c | (1 << bit) } else { c & !(1 << bit) };
    r.write64(MMIO_CONTROL, n);
}

// ── Memory owned by the backend ────────────────────────────────────

/// Zeroed, physically contiguous, naturally aligned block.
struct Block {
    phys: u64,
    order: u8,
}

impl Block {
    fn new(order: u8) -> Result<Self, IoError> {
        let f = narf_memory::alloc_pages_on(0, order)?;
        let phys = f.start_address().raw();
        // SAFETY: freshly allocated, exclusively owned block in the direct map.
        unsafe { core::ptr::write_bytes(ptr8(phys), 0, 4096 << order) };
        Ok(Self { phys, order })
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        narf_memory::free_pages(
            narf_memory::PhysFrame::new(narf_memory::PhysAddr::new(self.phys)),
            self.order,
        );
    }
}

#[inline]
fn ptr8(phys: u64) -> *mut u8 {
    narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>()
}

// ── Event log ──────────────────────────────────────────────────────

/// One decoded event-log entry (Linux `iommu_print_event`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AmdViEvent {
    pub unit: u8,
    pub kind: u8,
    pub devid: u16,
    /// Domain ID (IO_PAGE_FAULT) or PASID, as Linux's `pasid` field.
    pub domid_or_pasid: u32,
    pub address: u64,
    pub flags: u16,
}

impl AmdViEvent {
    /// Linux event decode from the four dwords.
    pub fn decode(unit: u8, e: [u32; 4]) -> Self {
        Self {
            unit,
            kind: ((e[1] >> 28) & 0xf) as u8,
            devid: e[0] as u16,
            domid_or_pasid: (e[0] & 0xf_0000) | (e[1] & 0xffff),
            address: ((e[3] as u64) << 32) | e[2] as u64,
            flags: ((e[1] >> 16) & 0xfff) as u16,
        }
    }

    /// IO_PAGE_FAULT `RW` flag: the faulting access was a write.
    pub fn is_write(&self) -> bool {
        self.flags & 0x020 != 0
    }
}

const RECENT_EVENTS: usize = 16;

/// Event counters (index = event type) and the last few events.
#[derive(Debug)]
struct EventStats {
    by_type: [AtomicU64; 16],
    overflows: AtomicU64,
    recent: IrqSafeSpinLock<Vec<AmdViEvent>>,
}

// ── Units and the backend ──────────────────────────────────────────

struct CmdRing {
    head: u32,
    tail: u32,
    /// Last completion-wait sequence number queued.
    seq: u64,
}

struct Unit {
    index: u8,
    regs: Box<dyn AmdViRegs>,
    mmio_phys: u64,
    efr: u64,
    ivhd_flags: u8,
    cmd_buf: Block,
    evt_buf: Block,
    /// Completion-wait semaphore page (Linux `cmd_sem`).
    sem: Block,
    ring: IrqSafeSpinLock<CmdRing>,
    evt_lock: IrqSafeSpinLock<()>,
}

/// Why [`bring_up`] failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpError {
    /// No IVHD unit on PCI segment 0.
    NoUnits,
    /// Register window could not be mapped.
    MapFailed,
    /// EFR read 0 / all-ones.
    DeadMmio,
    /// Table / ring allocation failed.
    NoMemory,
    /// The bring-up cache flush did not complete.
    FlushTimeout,
}

/// The AMD-Vi backend: all units of PCI segment 0 sharing one device
/// table.
pub struct AmdVi {
    dev_table: Block,
    units: Vec<Unit>,
    /// Requester ID → unit index (`u8::MAX` = no unit; Linux
    /// `rlookup_table`).
    rlookup: Vec<u8>,
    /// Requester ID → the ID the IOMMU sees (Linux `alias_table`).
    alias: Vec<u16>,
    /// Requester ID → IVHD DTE setting flags.
    acpi_flags: Vec<u8>,
    unity: Vec<UnityRange>,
    /// DTE owner per programmed requester ID: (domain ID, users).
    owners: IrqSafeSpinLock<BTreeMap<u16, (u16, u32)>>,
    dte_lock: IrqSafeSpinLock<()>,
    events: EventStats,
}

impl core::fmt::Debug for AmdVi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdVi")
            .field("dev_table", &self.dev_table.phys)
            .field("units", &self.units.len())
            .finish()
    }
}

fn now_ns() -> u64 {
    narf_time::wall::cycles_to_ns(narf_time::now_cycles())
}

impl Unit {
    fn regs(&self) -> &dyn AmdViRegs {
        &*self.regs
    }

    /// Linux `__iommu_queue_command_sync` + `copy_cmd_to_buffer`.
    fn queue(&self, ring: &mut CmdRing, cmd: Cmd) -> Result<(), IoError> {
        let next_tail = (ring.tail + CMD_ENTRY_SIZE) % CMD_BUFFER_SIZE;
        let mut deadline = None;
        while ring.head.wrapping_sub(next_tail) % CMD_BUFFER_SIZE <= 0x20 {
            let now = now_ns();
            match deadline {
                None => deadline = Some(now + WAIT_TIMEOUT_NS),
                Some(d) if now > d => return Err(IoError::Timeout),
                Some(_) => core::hint::spin_loop(),
            }
            ring.head = self.regs().read32(MMIO_CMD_HEAD) % CMD_BUFFER_SIZE;
        }
        let slot = ptr8(self.cmd_buf.phys).wrapping_add(ring.tail as usize) as *mut u32;
        for (i, w) in cmd.iter().enumerate() {
            // SAFETY: `tail + 16 <= CMD_BUFFER_SIZE`; the ring is owned here.
            unsafe { core::ptr::write_volatile(slot.add(i), *w) };
        }
        // Entry stores are visible before the tail doorbell.
        fence(Ordering::SeqCst);
        ring.tail = next_tail;
        self.regs().write32(MMIO_CMD_TAIL, next_tail);
        Ok(())
    }

    /// Queue `cmds`, then `COMPLETION_WAIT`, and poll the semaphore
    /// (Linux `iommu_completion_wait` / `wait_on_sem`).
    fn run(&self, cmds: &[Cmd]) -> Result<(), IoError> {
        let seq = {
            let mut ring = self.ring.lock();
            for c in cmds {
                self.queue(&mut ring, *c)?;
            }
            ring.seq += 1;
            let seq = ring.seq;
            self.queue(&mut ring, cmd_completion_wait(self.sem.phys, seq))?;
            seq
        };
        let sem = narf_memory::PhysAddr::new(self.sem.phys).kernel_ptr::<u64>();
        let deadline = now_ns() + WAIT_TIMEOUT_NS;
        loop {
            // SAFETY: the semaphore page is owned by this unit; the IOMMU
            // stores to it coherently.
            let v = unsafe { core::ptr::read_volatile(sem) };
            if (v.wrapping_sub(seq) as i64) >= 0 {
                return Ok(());
            }
            if now_ns() > deadline {
                return Err(IoError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
}

impl AmdVi {
    /// Number of units driven.
    pub fn unit_count(&self) -> usize {
        self.units.len()
    }

    /// Physical base of the shared device table.
    pub fn dev_table_phys(&self) -> u64 {
        self.dev_table.phys
    }

    /// Command-buffer / event-log / semaphore physical bases of `unit`.
    pub fn unit_rings(&self, unit: usize) -> Option<(u64, u64, u64)> {
        self.units
            .get(unit)
            .map(|u| (u.cmd_buf.phys, u.evt_buf.phys, u.sem.phys))
    }

    /// MMIO base and EFR of `unit`.
    pub fn unit_info(&self, unit: usize) -> Option<(u64, u64)> {
        self.units.get(unit).map(|u| (u.mmio_phys, u.efr))
    }

    /// Requester ID the IOMMU sees for `devid`.
    pub fn alias_of(&self, devid: u16) -> u16 {
        self.alias[devid as usize]
    }

    /// Unit translating `devid`, if any IVHD covers it.
    pub fn unit_of(&self, devid: u16) -> Option<usize> {
        match self.rlookup[devid as usize] {
            u8::MAX => None,
            u => Some(u as usize),
        }
    }

    /// Current DTE of `devid`.
    pub fn read_dte(&self, devid: u16) -> Dte {
        let p = ptr8(self.dev_table.phys).wrapping_add(devid as usize * DTE_SIZE) as *const u64;
        // SAFETY: devid < 65536 entries of the owned 2 MiB table.
        unsafe { core::array::from_fn(|i| core::ptr::read_volatile(p.add(i))) }
    }

    fn initial(&self, devid: u16) -> Dte {
        dte_initial(self.acpi_flags[devid as usize])
    }

    /// Store a DTE so the IOMMU never fetches a mix of old and new
    /// translation fields: upper half first, then a blocking low quadword,
    /// the domain ID, and finally the new low quadword (Linux writes the
    /// low 128 bits with one `cmpxchg16b`; every intermediate state here
    /// is either the old entry, blocking, or the new entry).
    fn write_dte(&self, devid: u16, new: Dte) {
        let _g = self.dte_lock.lock();
        let p = ptr8(self.dev_table.phys).wrapping_add(devid as usize * DTE_SIZE) as *mut u64;
        // SAFETY: devid < 65536 entries of the owned 2 MiB table; aligned
        // 64-bit stores are single-copy atomic for the walker.
        unsafe {
            core::ptr::write_volatile(p.add(3), new[3]);
            core::ptr::write_volatile(p.add(2), new[2]);
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(p, dte_blocked(self.initial(devid))[0]);
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(p.add(1), new[1]);
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(p, new[0]);
        }
        fence(Ordering::SeqCst);
    }

    /// `devid` and its alias, deduplicated (Linux `clone_aliases`).
    fn requesters(&self, bdf: Bdf) -> ([u16; 2], usize) {
        let d = bdf.raw();
        let a = self.alias_of(d);
        if a == d {
            ([d, d], 1)
        } else {
            ([d, a], 2)
        }
    }

    /// Drain `unit`'s event log (Linux `iommu_poll_events` +
    /// `amd_iommu_restart_event_logging` on overflow). Returns the number
    /// of entries consumed.
    fn poll_unit(&self, u: &Unit) -> usize {
        let _g = u.evt_lock.lock();
        let r = u.regs();
        let mut head = r.read32(MMIO_EVT_HEAD) % EVTLOG_SIZE;
        let tail = r.read32(MMIO_EVT_TAIL) % EVTLOG_SIZE;
        let mut n = 0;
        while head != tail {
            let p = ptr8(u.evt_buf.phys).wrapping_add(head as usize) as *mut u32;
            // SAFETY: head + 16 <= EVTLOG_SIZE inside the owned log.
            let e: [u32; 4] =
                unsafe { core::array::from_fn(|i| core::ptr::read_volatile(p.add(i))) };
            let ev = AmdViEvent::decode(u.index, e);
            if ev.kind == 0 {
                // Erratum 732: the entry is not written yet; retry on the
                // next poll rather than consuming it.
                break;
            }
            self.events.by_type[ev.kind as usize].fetch_add(1, Ordering::Relaxed);
            {
                let mut recent = self.events.recent.lock();
                if recent.len() == RECENT_EVENTS {
                    recent.remove(0);
                }
                recent.push(ev);
            }
            // SAFETY: as above; cleared for the erratum-732 check.
            unsafe { core::ptr::write_bytes(p, 0, 4) };
            head = (head + EVTLOG_ENTRY_SIZE) % EVTLOG_SIZE;
            r.write32(MMIO_EVT_HEAD, head);
            n += 1;
        }
        if r.read64(MMIO_STATUS) & MMIO_STATUS_EVT_OVERFLOW != 0 {
            self.events.overflows.fetch_add(1, Ordering::Relaxed);
            feature_set(r, CONTROL_EVT_LOG_EN, false);
            r.write64(MMIO_STATUS, MMIO_STATUS_EVT_OVERFLOW);
            feature_set(r, CONTROL_EVT_LOG_EN, true);
        }
        n
    }

    /// Drain every unit's event log.
    pub fn poll_events(&self) -> usize {
        self.units.iter().map(|u| self.poll_unit(u)).sum()
    }

    /// Count of logged events of `kind` (e.g. [`EVENT_TYPE_IO_FAULT`]).
    pub fn event_count(&self, kind: u8) -> u64 {
        self.events.by_type[(kind & 0xf) as usize].load(Ordering::Relaxed)
    }

    /// Event-log overflows seen.
    pub fn event_overflows(&self) -> u64 {
        self.events.overflows.load(Ordering::Relaxed)
    }

    /// The last few logged events, oldest first.
    pub fn recent_events(&self) -> Vec<AmdViEvent> {
        self.events.recent.lock().clone()
    }

    fn run_on(&self, unit: usize, cmds: &[Cmd]) -> Result<(), IoError> {
        let u = &self.units[unit];
        let r = u.run(cmds);
        self.poll_unit(u);
        r
    }

    fn unit_for(&self, bdf: Bdf) -> Result<usize, IoError> {
        let (ids, n) = self.requesters(bdf);
        let unit = self.unit_of(ids[0]).ok_or(IoError::NotMapped)?;
        if n == 2 && self.unit_of(ids[1]).is_some_and(|u| u != unit) {
            return Err(IoError::NotMapped);
        }
        Ok(unit)
    }

    /// IVMD unity ranges that apply to `bdf` or its alias (Linux
    /// `amd_iommu_get_resv_regions`, `IOMMU_RESV_DIRECT`).
    pub fn unity_ranges(&self, bdf: Bdf) -> Vec<UnityRange> {
        let (ids, n) = self.requesters(bdf);
        self.unity
            .iter()
            .filter(|r| ids[..n].iter().any(|&d| r.first <= d && d <= r.last))
            .copied()
            .collect()
    }
}

impl IommuHw for AmdVi {
    fn name(&self) -> &'static str {
        "amd-vi"
    }

    fn format(&self) -> PageTableFormat {
        PageTableFormat::AmdV1
    }

    /// `CONTROL_COHERENT_EN` is always set: walks snoop CPU caches.
    fn coherent_walk(&self) -> bool {
        true
    }

    /// Linux `set_dte_entry` (v1) for the device and its alias, then
    /// `device_flush_dte` + `iommu_completion_wait`.
    fn attach(&self, bdf: Bdf, domain_id: u16, root: u64, levels: u8) -> Result<(), IoError> {
        if domain_id == 0 || !(1..=6).contains(&levels) || root & 0xfff != 0 {
            return Err(IoError::DomainMismatch);
        }
        let unit = self.unit_for(bdf)?;
        let (ids, n) = self.requesters(bdf);
        {
            let mut owners = self.owners.lock();
            for &d in &ids[..n] {
                if let Some(&(dom, _)) = owners.get(&d) {
                    if dom != domain_id {
                        return Err(IoError::DomainMismatch);
                    }
                }
            }
            for &d in &ids[..n] {
                owners.entry(d).or_insert((domain_id, 0)).1 += 1;
            }
        }
        let mut cmds = [[0u32; 4]; 2];
        for (i, &d) in ids[..n].iter().enumerate() {
            self.write_dte(d, dte_translated(self.initial(d), root, levels, domain_id));
            cmds[i] = cmd_inv_dte(d);
        }
        let res = self.run_on(unit, &cmds[..n]);
        if res.is_err() {
            // Unconfirmed invalidation: fail closed (blocked), forget the
            // attachment so io never treats the device as translated.
            let mut owners = self.owners.lock();
            for &d in &ids[..n] {
                self.write_dte(d, dte_blocked(self.initial(d)));
                if let Some((_, users)) = owners.get_mut(&d) {
                    *users -= 1;
                    if *users == 0 {
                        owners.remove(&d);
                    }
                }
            }
        }
        res
    }

    /// Trait contract: block the device. Blocking DTE (`TV`, `Mode = 0`,
    /// no `IR`/`IW`) for the device and — when no other attached device
    /// shares it — its alias; then `INVALIDATE_DEVTAB_ENTRY` and
    /// `INVALIDATE_IOMMU_PAGES` for the whole domain, then completion wait.
    fn detach(&self, bdf: Bdf, domain_id: u16) -> Result<(), IoError> {
        let unit = self.unit_for(bdf)?;
        let (ids, n) = self.requesters(bdf);
        let mut cmds = Vec::with_capacity(3);
        {
            let mut owners = self.owners.lock();
            if ids[..n]
                .iter()
                .any(|d| owners.get(d).is_none_or(|&(dom, _)| dom != domain_id))
            {
                return Err(IoError::NotMapped);
            }
            for &d in &ids[..n] {
                let last = match owners.get_mut(&d) {
                    Some((_, users)) => {
                        *users -= 1;
                        *users == 0
                    }
                    None => false,
                };
                if last {
                    owners.remove(&d);
                    self.write_dte(d, dte_blocked(self.initial(d)));
                    cmds.push(cmd_inv_dte(d));
                }
            }
        }
        cmds.push(cmd_inv_iommu_pages(domain_id, 0, u64::MAX));
        self.run_on(unit, &cmds)
    }

    /// Linux `domain_flush_pages_v1` + `domain_flush_complete` on every
    /// unit (one per segment-0 IOMMU; usually one).
    fn flush_iotlb(&self, domain_id: u16, iova: u64, len: u64) -> Result<(), IoError> {
        if len == 0 {
            return Ok(());
        }
        let last = iova.saturating_add(len - 1);
        let cmd = cmd_inv_iommu_pages(domain_id, iova, last);
        let mut res = Ok(());
        for i in 0..self.units.len() {
            if let Err(e) = self.run_on(i, &[cmd]) {
                res = Err(e);
            }
        }
        res
    }

    fn direct_mappings(&self, bdf: Bdf) -> Vec<DirectMapping> {
        self.unity_ranges(bdf)
            .into_iter()
            .map(|r| DirectMapping {
                start: r.start,
                end: r.end,
                perms: IommuPerms::from_bits(r.prot),
            })
            .collect()
    }
}

/// Linux `early_enable_iommu` for one unit (after the device table holds
/// pass-through entries).
fn enable_unit(u: &Unit, dev_table_phys: u64) -> Result<(), BringUpError> {
    use ivrs::{
        IVHD_FLAG_HT_TUN_EN, IVHD_FLAG_ISOC_EN, IVHD_FLAG_PASSPW_EN, IVHD_FLAG_RESPASSPW_EN,
    };
    let r = u.regs();
    // iommu_disable
    for bit in [
        CONTROL_CMDBUF_EN,
        CONTROL_EVT_INT_EN,
        CONTROL_EVT_LOG_EN,
        CONTROL_GALOG_EN,
        CONTROL_GAINT_EN,
        CONTROL_PPRLOG_EN,
        CONTROL_PPRINT_EN,
        CONTROL_IOMMU_EN,
        CONTROL_IRTCACHEDIS,
    ] {
        feature_set(r, bit, false);
    }
    // iommu_init_flags
    feature_set(
        r,
        CONTROL_HT_TUN_EN,
        u.ivhd_flags & IVHD_FLAG_HT_TUN_EN != 0,
    );
    feature_set(
        r,
        CONTROL_PASSPW_EN,
        u.ivhd_flags & IVHD_FLAG_PASSPW_EN != 0,
    );
    feature_set(
        r,
        CONTROL_RESPASSPW_EN,
        u.ivhd_flags & IVHD_FLAG_RESPASSPW_EN != 0,
    );
    feature_set(r, CONTROL_ISOC_EN, u.ivhd_flags & IVHD_FLAG_ISOC_EN != 0);
    feature_set(r, CONTROL_COHERENT_EN, true);
    let c = r.read64(MMIO_CONTROL) & !(CTRL_INV_TO_MASK << CONTROL_INV_TIMEOUT);
    r.write64(MMIO_CONTROL, c | (CTRL_INV_TO_1S << CONTROL_INV_TIMEOUT));
    // iommu_set_device_table: size field = (2 MiB >> 12) - 1.
    r.write64(
        MMIO_DEV_TABLE,
        dev_table_phys | (((DEV_TABLE_ENTRIES * DTE_SIZE) >> 12) as u64 - 1),
    );
    // iommu_enable_command_buffer + amd_iommu_reset_cmd_buffer
    r.write64(MMIO_CMD_BUF, u.cmd_buf.phys | MMIO_CMD_SIZE_512);
    feature_set(r, CONTROL_CMDBUF_EN, false);
    r.write32(MMIO_CMD_HEAD, 0);
    r.write32(MMIO_CMD_TAIL, 0);
    {
        let mut ring = u.ring.lock();
        ring.head = 0;
        ring.tail = 0;
    }
    feature_set(r, CONTROL_CMDBUF_EN, true);
    // iommu_enable
    feature_set(r, CONTROL_IOMMU_EN, true);
    // amd_iommu_flush_all_caches (no IRT: interrupt remapping is off).
    let flushed = if u.efr & FEATURE_IA != 0 {
        u.run(&[cmd_inv_all()])
    } else {
        flush_all_slow(u)
    };
    flushed.map_err(|_| BringUpError::FlushTimeout)?;
    // iommu_enable_event_buffer
    r.write64(MMIO_EVT_BUF, u.evt_buf.phys | EVTLOG_LEN_MASK_DEF);
    r.write32(MMIO_EVT_HEAD, 0);
    r.write32(MMIO_EVT_TAIL, 0);
    feature_set(r, CONTROL_EVT_LOG_EN, true);
    Ok(())
}

/// Linux `amd_iommu_flush_dte_all` + `amd_iommu_flush_tlb_all` for units
/// without `FEATURE_IA`.
fn flush_all_slow(u: &Unit) -> Result<(), IoError> {
    const BATCH: usize = 256;
    let mut batch = Vec::with_capacity(BATCH);
    for devid in 0..=u16::MAX {
        batch.push(cmd_inv_dte(devid));
        if batch.len() == BATCH {
            u.run(&batch)?;
            batch.clear();
        }
    }
    for domid in 0..=u16::MAX {
        batch.push(cmd_inv_iommu_pages(domid, 0, u64::MAX));
        if batch.len() == BATCH {
            u.run(&batch)?;
            batch.clear();
        }
    }
    u.run(&batch)
}

/// Bring up every segment-0 unit of `info`. `map` produces each unit's
/// register access ([`MmioRegs::map`] on hardware). On failure every unit
/// already touched is disabled again before the tables are freed.
pub fn bring_up(
    info: &IvrsInfo,
    map: &dyn Fn(&IvhdUnit) -> Option<Box<dyn AmdViRegs>>,
) -> Result<AmdVi, BringUpError> {
    let seg0: Vec<&IvhdUnit> = info
        .units
        .iter()
        .filter(|u| u.pci_seg == 0)
        .take(u8::MAX as usize - 1)
        .collect();
    if seg0.is_empty() {
        return Err(BringUpError::NoUnits);
    }
    let nomem = |_| BringUpError::NoMemory;
    let dev_table = Block::new(DEV_TABLE_ORDER).map_err(nomem)?;
    let mut rlookup = alloc::vec![u8::MAX; DEV_TABLE_ENTRIES];
    let mut alias: Vec<u16> = (0..=u16::MAX).collect();
    let mut acpi_flags = alloc::vec![0u8; DEV_TABLE_ENTRIES];
    let mut flagged = alloc::vec![false; DEV_TABLE_ENTRIES];
    let mut units = Vec::with_capacity(seg0.len());
    for (i, iv) in seg0.iter().enumerate() {
        for d in &iv.devices {
            for id in d.first..=d.last {
                rlookup[id as usize] = i as u8;
                // First flagged range wins (Linux `search_ivhd_dte_flags`).
                if d.flags != 0 && !flagged[id as usize] {
                    flagged[id as usize] = true;
                    acpi_flags[id as usize] = d.flags;
                }
            }
        }
        for a in &iv.aliases {
            for id in a.first..=a.last {
                alias[id as usize] = a.alias;
            }
        }
        let regs = map(iv).ok_or(BringUpError::MapFailed)?;
        let efr = regs.read64(MMIO_EXT_FEATURES);
        if efr == 0 || efr == u64::MAX {
            return Err(BringUpError::DeadMmio);
        }
        units.push(Unit {
            index: i as u8,
            regs,
            mmio_phys: iv.mmio_phys,
            efr,
            ivhd_flags: iv.flags,
            cmd_buf: Block::new(1).map_err(nomem)?,
            evt_buf: Block::new(1).map_err(nomem)?,
            sem: Block::new(0).map_err(nomem)?,
            ring: IrqSafeSpinLock::new(CmdRing {
                head: 0,
                tail: 0,
                seq: 0,
            }),
            evt_lock: IrqSafeSpinLock::new(()),
        });
    }
    let hw = AmdVi {
        dev_table,
        units,
        rlookup,
        alias,
        acpi_flags,
        unity: info
            .unity
            .iter()
            .filter(|r| r.pci_seg == 0)
            .copied()
            .collect(),
        owners: IrqSafeSpinLock::new(BTreeMap::new()),
        dte_lock: IrqSafeSpinLock::new(()),
        events: EventStats {
            by_type: core::array::from_fn(|_| AtomicU64::new(0)),
            overflows: AtomicU64::new(0),
            recent: IrqSafeSpinLock::new(Vec::new()),
        },
    };
    // Every DTE pass-through before any unit is enabled.
    let base = ptr8(hw.dev_table.phys) as *mut u64;
    for devid in 0..DEV_TABLE_ENTRIES {
        let d = dte_passthrough(dte_initial(hw.acpi_flags[devid]));
        for (i, q) in d.iter().enumerate() {
            // SAFETY: inside the owned 2 MiB table; not yet visible to HW.
            unsafe { core::ptr::write_volatile(base.add(devid * 4 + i), *q) };
        }
    }
    fence(Ordering::SeqCst);
    for (i, u) in hw.units.iter().enumerate() {
        if let Err(e) = enable_unit(u, hw.dev_table.phys) {
            for done in &hw.units[..=i] {
                disable_unit(done);
            }
            return Err(e);
        }
    }
    Ok(hw)
}

/// Linux `iommu_disable` (used to unwind a failed bring-up).
fn disable_unit(u: &Unit) {
    for bit in [
        CONTROL_CMDBUF_EN,
        CONTROL_EVT_INT_EN,
        CONTROL_EVT_LOG_EN,
        CONTROL_IOMMU_EN,
    ] {
        feature_set(u.regs(), bit, false);
    }
}

// ── Boot glue ──────────────────────────────────────────────────────

static ACTIVE: IrqSafeSpinLock<Option<&'static AmdVi>> = IrqSafeSpinLock::new(None);

/// The live backend, once [`crate::iommu::init`] enabled it.
pub fn active() -> Option<&'static AmdVi> {
    *ACTIVE.lock()
}

/// Drain the live backend's event logs (0 when inactive).
pub fn poll_events() -> usize {
    active().map_or(0, |a| a.poll_events())
}

/// Why the opt-in AMD-Vi enable did not happen.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EnableError {
    /// `narf_acpi` kept no IVRS copy.
    NoIvrs,
    Ivrs(ivrs::IvrsError),
    BringUp(BringUpError),
}

/// Parse the boot IVRS, bring the units up and leak the backend for
/// [`crate::iommu::enable_per_domain`].
pub fn boot_enable() -> Result<&'static AmdVi, EnableError> {
    let table = narf_acpi::ivrs_table_copy().ok_or(EnableError::NoIvrs)?;
    let info = ivrs::parse(&table).map_err(EnableError::Ivrs)?;
    let map = |u: &IvhdUnit| -> Option<Box<dyn AmdViRegs>> {
        // SAFETY: `mmio_phys` comes from an IVHD block of the firmware IVRS.
        unsafe { MmioRegs::map(u.mmio_phys) }.map(|m| Box::new(m) as Box<dyn AmdViRegs>)
    };
    let hw: &'static AmdVi = Box::leak(Box::new(
        bring_up(&info, &map).map_err(EnableError::BringUp)?,
    ));
    *ACTIVE.lock() = Some(hw);
    Ok(hw)
}
