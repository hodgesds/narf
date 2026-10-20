//! GICv3 ITS (Interrupt Translation Service) bring-up and MSI mapping.
//!
//! On aarch64 with GICv3+ITS the MSI delivery path is:
//!
//!   device → MSI write → `GITS_TRANSLATER` → ITS (DeviceID, EventID)
//!     → ITT entry → LPI INTID + collection → redistributor → CPU.
//!
//! Bring-up follows Linux `drivers/irqchip/irq-gic-v3-its.c`:
//!
//! - **Discovery** ([`discover_firmware`]): the ITS base, redistributor
//!   regions and PCI DeviceID mappings come from the ACPI MADT/IORT when an
//!   RSDP is known, else from the devicetree (`arm,gic-v3`,
//!   `arm,gic-v3-its`, `msi-map`). With neither, the QEMU `virt` layout is
//!   assumed and that is logged.
//! - **Tables** (`its_alloc_tables`): every `GITS_BASER<n>` is probed for
//!   its type, entry size and an accepted page size (64K → 16K → 4K); flat
//!   device / collection tables are sized from `GITS_TYPER.Devbits` and
//!   the collection count; shareability / cacheability are read back and
//!   tables are cleaned to PoC when the ITS reports non-shareable.
//! - **LPIs** (`its_alloc_lpi_tables` / `its_cpu_init_lpis`): the property
//!   table covers the configured IDbits, each byte holds priority + group,
//!   and an LPI's enable bit is set when it is mapped (then INV + SYNC);
//!   the pending table is 64 KiB aligned; PROPBASER / PENDBASER attributes
//!   are read back. The BSP's redistributor is found by `GICR_TYPER`
//!   affinity, not by a fixed offset.
//! - **Devices** (`its_create_device`): each DeviceID gets a real ITT
//!   (`nr_ites × ITT_entry_size`, 256-byte aligned) and `MAPD` carries its
//!   address and `Size = ilog2(nr_ites) - 1`; later maps reuse it;
//!   [`unmap_event`] / [`free_device`] tear down with DISCARD / MAPD V=0.
//! - **Commands**: a 64 KiB queue under `CMD_LOCK`, bounded `GITS_CREADR`
//!   polling, wrap handling, and `GITS_CREADR.Stalled` reported as an error.
//!
//! What stays QEMU-shaped: only one ITS is driven (the first described),
//! every LPI targets collection 0 on the BSP, and the distributor /
//! per-CPU redistributor setup in `gic.rs` still uses QEMU `virt` bases.

use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::its_core::{
    self as itsc, reg, Cmd, CmdHw, CmdQueue, ItsTyper, Mmio64, Poll, SetupError, TableMem, Tables,
};
use crate::its_fw::{self, GicFirmware, Source};

/// QEMU virt GICv3 ITS frame base (fallback when firmware is silent).
const QEMU_ITS_BASE: u64 = 0x0808_0000;
/// QEMU virt redistributor region (`VIRT_GIC_REDIST`).
const QEMU_GICR_BASE: u64 = 0x080A_0000;
const QEMU_GICR_LEN: u64 = 0x00F6_0000;

/// First LPI INTID (per GIC architecture, fixed).
pub const LPI_BASE: u32 = itsc::LPI_BASE;
/// LPIs provisioned: one per logical vector slot (`INTID = LPI_BASE +
/// vector`, see `vector.rs`).
pub const NUM_LPIS: u32 = 256;
/// ITT size `map_event` gives a device it has to create on the fly:
/// EventIDs are the 8-bit logical vectors the MSI helpers pass.
pub const DEFAULT_DEVICE_EVENTS: u32 = 256;

static INIT_DONE: AtomicBool = AtomicBool::new(false);
/// ITS control-frame physical base in use (QEMU default until discovery).
static ITS_PA: AtomicU64 = AtomicU64::new(QEMU_ITS_BASE);
static ITS_VA: AtomicUsize = AtomicUsize::new(0);
/// Early QEMU-default redistributor mapping made by [`remap_mmio`].
static EARLY_GICR_VA: AtomicUsize = AtomicUsize::new(0);
/// Layout source recorded by discovery (`Source as u8`).
static SOURCE: AtomicU8 = AtomicU8::new(0);
static FIRMWARE: IrqSafeSpinLock<Option<GicFirmware>> = IrqSafeSpinLock::new(None);

/// Live ITS state. Lock order: `STATE` before `CMD_LOCK`.
struct Its {
    typer: ItsTyper,
    tables: Tables,
    device_ids: u64,
    id_bits: u32,
    prop_pa: u64,
    prop_bytes: u64,
    prop_flush: bool,
    pend_pa: u64,
    rd_pa: u64,
    rd_va: usize,
    rd_target: u64,
    devices: Vec<Device>,
}

struct Device {
    id: u32,
    itt_pa: u64,
    itt_order: u8,
    nr_ites: u32,
    /// `(event, lpi)` pairs currently mapped.
    events: Vec<(u32, u32)>,
}

static STATE: IrqSafeSpinLock<Option<Its>> = IrqSafeSpinLock::new(None);

/// Command-queue state. Holding this lock serialises queue writes, the
/// `GITS_CWRITER` bump and the `GITS_CREADR` poll.
struct CmdState {
    queue: CmdQueue,
    va: usize,
    flush: bool,
}

static CMD_LOCK: IrqSafeSpinLock<Option<CmdState>> = IrqSafeSpinLock::new(None);

/// ITS-init / command-issue error surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ItsError {
    /// Backing-page allocation failed.
    NoMemory,
    /// A register did not settle (e.g. `GITS_CTLR.Quiescent`).
    InitTimeout,
    /// Command queue didn't drain within the bounded poll.
    CmdTimeout,
    /// `GITS_CREADR.Stalled`: the ITS rejected the command at `offset`.
    CmdStalled { offset: u64 },
    /// `init_bsp` has not completed.
    NotInitialised,
    /// Table / LPI programming refused (see [`SetupError`]).
    Setup(SetupError),
    /// No redistributor frame matches the BSP's affinity.
    NoRedistributor,
    /// DeviceID beyond the provisioned device table / `Devbits`.
    DeviceIdOutOfRange,
    /// EventID beyond the device's ITT.
    EventOutOfRange,
    /// LPI outside `LPI_BASE..LPI_BASE + NUM_LPIS`.
    LpiOutOfRange,
    /// DeviceID has no ITT (unmap of an unknown device / event).
    UnknownDevice,
    /// An existing ITT is smaller than the requested vector count.
    IttTooSmall,
}

impl From<SetupError> for ItsError {
    fn from(e: SetupError) -> Self {
        match e {
            SetupError::NoMemory => ItsError::NoMemory,
            e => ItsError::Setup(e),
        }
    }
}

impl From<itsc::CmdError> for ItsError {
    fn from(e: itsc::CmdError) -> Self {
        match e {
            itsc::CmdError::Timeout => ItsError::CmdTimeout,
            itsc::CmdError::Stalled { offset } => ItsError::CmdStalled { offset },
        }
    }
}

impl From<narf_memory::FrameAllocError> for ItsError {
    fn from(_: narf_memory::FrameAllocError) -> Self {
        ItsError::NoMemory
    }
}

// ── MMIO windows ────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct Regs {
    va: usize,
}

impl Mmio64 for Regs {
    fn read32(&mut self, off: usize) -> u32 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: `va` is a live Device mapping of a GIC frame covering `off`.
        let v = unsafe { core::ptr::read_volatile((self.va + off) as *const u32) };
        compiler_fence(Ordering::SeqCst);
        v
    }
    fn write32(&mut self, off: usize, v: u32) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.va + off) as *mut u32, v) };
        compiler_fence(Ordering::SeqCst);
    }
    fn read64(&mut self, off: usize) -> u64 {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: as above; 64-bit GIC registers are 8-byte aligned.
        let v = unsafe { core::ptr::read_volatile((self.va + off) as *const u64) };
        compiler_fence(Ordering::SeqCst);
        v
    }
    fn write64(&mut self, off: usize, v: u64) {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile((self.va + off) as *mut u64, v) };
        compiler_fence(Ordering::SeqCst);
    }
}

/// ITS registers + command memory, for `its_core::submit`.
struct CmdPort<'a> {
    regs: Regs,
    st: &'a CmdState,
}

impl Mmio64 for CmdPort<'_> {
    fn read32(&mut self, off: usize) -> u32 {
        self.regs.read32(off)
    }
    fn write32(&mut self, off: usize, v: u32) {
        self.regs.write32(off, v)
    }
    fn read64(&mut self, off: usize) -> u64 {
        self.regs.read64(off)
    }
    fn write64(&mut self, off: usize, v: u64) {
        self.regs.write64(off, v)
    }
}

impl CmdHw for CmdPort<'_> {
    fn write_cmd(&mut self, off: u64, cmd: &Cmd) {
        let p = (self.st.va + off as usize) as *mut u64;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: `off` is a 32-byte slot inside the queue `init_bsp`
        // allocated; reached through the direct map.
        unsafe {
            for (i, w) in cmd.iter().enumerate() {
                core::ptr::write_volatile(p.add(i), *w);
            }
        }
        if self.st.flush {
            // SAFETY: same 32 bytes of mapped kernel memory.
            unsafe { narf_arch::aarch64::cache::clean_inval_to_poc(p as usize, 32) };
        } else {
            narf_arch::aarch64::cache::dsb_ishst();
        }
    }
    fn spin(&mut self, poll: &mut dyn FnMut(&mut Self) -> Poll) -> Poll {
        // Linux bounds each wait at ~1 s. responsive_spin_until keeps the
        // FB / serial pumps alive on a wedged ITS.
        let mut last = Poll::Pending;
        narf_scheduler::responsive_spin_until(
            || {
                last = poll(self);
                last != Poll::Pending
            },
            narf_time::Deadline::after_ms(1000),
        );
        last
    }
}

/// Frame-allocator backing for ITS / LPI tables.
struct FrameMem;

fn order_for(bytes: u64) -> u8 {
    let pages = bytes.div_ceil(narf_memory::PAGE_SIZE).max(1);
    pages.next_power_of_two().trailing_zeros() as u8
}

impl TableMem for FrameMem {
    fn alloc(&mut self, bytes: u64, align: u64) -> Option<u64> {
        let order = order_for(bytes.max(align));
        let frame = narf_memory::frame::alloc_pages_on(0, order).ok()?;
        let pa = frame.start_address().raw();
        if pa & (align - 1) != 0 {
            narf_memory::frame::free_pages(frame, order);
            return None;
        }
        let len = (narf_memory::PAGE_SIZE << order) as usize;
        // SAFETY: freshly allocated block, reached through the direct map.
        unsafe { core::ptr::write_bytes(PhysAddr::new(pa).kernel_mut_ptr::<u8>(), 0, len) };
        Some(pa)
    }
    fn free(&mut self, pa: u64, bytes: u64) {
        narf_memory::frame::free_pages(
            narf_memory::PhysFrame::new(PhysAddr::new(pa)),
            order_for(bytes),
        );
    }
    fn flush(&mut self, pa: u64, bytes: u64) {
        // SAFETY: table memory owned by the ITS driver, direct-mapped.
        unsafe {
            narf_arch::aarch64::cache::clean_inval_to_poc(
                PhysAddr::new(pa).kernel_ptr::<u8>() as usize,
                bytes as usize,
            )
        };
    }
}

/// Map a GIC frame (Device attributes). `ioremap` caches identical
/// requests, so mapping the frame `gic.rs` already mapped is free.
fn map(pa: u64, len: u64) -> Option<usize> {
    // SAFETY: firmware-described (or QEMU-default) GIC MMIO frame.
    unsafe { narf_memory::ioremap::ioremap(pa, len, narf_memory::ioremap::MmioAttrs::Device) }
        .ok()
        .map(|m| m.va() as usize)
}

/// Move the QEMU-default ITS and CPU-0 redistributor onto `ioremap`
/// windows. Runs at the MMU handoff, before firmware discovery; `init_bsp`
/// remaps if discovery later finds different frames.
pub fn remap_mmio() {
    if ITS_VA.load(Ordering::Acquire) == 0 {
        if let Some(va) = map(ITS_PA.load(Ordering::Acquire), reg::ITS_FRAME_LEN) {
            ITS_VA.store(va, Ordering::Release);
        }
    }
    if EARLY_GICR_VA.load(Ordering::Acquire) == 0 {
        if let Some(va) = map(QEMU_GICR_BASE, reg::GICR_STRIDE_V3) {
            EARLY_GICR_VA.store(va, Ordering::Release);
        }
    }
}

// ── Discovery ───────────────────────────────────────────────────────

/// Read the ITS / redistributor layout and PCI MSI mappings from firmware.
/// ACPI (MADT + IORT) wins when an RSDP is cached; otherwise `dtb` is
/// parsed. No-op once [`init_bsp`] has run, and a call that finds nothing
/// keeps an earlier result. Returns the source in effect.
///
/// # Safety
/// `dtb`, when `Some`, must be a live flattened devicetree reachable
/// through the direct map; cached ACPI tables likewise.
pub unsafe fn discover_firmware(dtb: Option<PhysAddr>) -> Source {
    if INIT_DONE.load(Ordering::Acquire) {
        return source();
    }
    let mut fw = GicFirmware::default();
    if let Some(rsdp) = narf_acpi::cached_rsdp() {
        // SAFETY: caller contract — ACPI tables are direct-mapped.
        unsafe { acpi_tables(rsdp, &mut fw) };
    }
    if fw.its.is_empty() {
        if let Some(dtb) = dtb {
            let mut dt = GicFirmware::default();
            let p = dtb.kernel_ptr::<u8>();
            // SAFETY: caller contract; the header is 40 bytes and
            // `parse_fdt` bounds every access by `totalsize`.
            let head = unsafe { core::slice::from_raw_parts(p, 40) };
            if let Some(total) = its_fw::fdt_total_size(head) {
                // SAFETY: the blob spans `totalsize` bytes.
                let blob = unsafe { core::slice::from_raw_parts(p, total) };
                if its_fw::parse_fdt(blob, &mut dt) {
                    fw = dt;
                }
            }
        }
    }
    let Some(its) = fw.primary_its() else {
        return source();
    };
    if fw.its.len() > 1 {
        let _ = writeln!(
            narf_console::Writer,
            "  its: {} ITSes described; driving only the first @ {:#x}",
            fw.its.len(),
            its.base
        );
    }
    ITS_PA.store(its.base, Ordering::Release);
    SOURCE.store(fw.source as u8, Ordering::Release);
    *FIRMWARE.lock() = Some(fw);
    source()
}

/// Copy the MADT + IORT out of the ACPI tables.
unsafe fn acpi_tables(rsdp: PhysAddr, fw: &mut GicFirmware) {
    // SAFETY: caller contract.
    let Ok(xsdt) = (unsafe { narf_acpi::parse_rsdp(rsdp) }) else {
        return;
    };
    let mut found: [(u64, u32); 2] = [(0, 0); 2];
    // SAFETY: caller contract — XSDT and children direct-mapped.
    let _ = unsafe {
        narf_acpi::walk_xsdt(xsdt, |phys, hdr| match &hdr.signature {
            b"APIC" if found[0].0 == 0 => found[0] = (phys, hdr.length),
            b"IORT" if found[1].0 == 0 => found[1] = (phys, hdr.length),
            _ => {}
        })
    };
    for (i, (phys, len)) in found.into_iter().enumerate() {
        if phys == 0 || len < 36 {
            continue;
        }
        // SAFETY: table spans its header's `length`.
        let t = unsafe {
            core::slice::from_raw_parts(PhysAddr::new(phys).kernel_ptr::<u8>(), len as usize)
        };
        if i == 0 {
            its_fw::parse_madt(t, fw);
        } else {
            fw.iort = Some(t.to_vec());
        }
    }
}

/// Where the ITS layout came from (`Source::None` = QEMU defaults).
pub fn source() -> Source {
    match SOURCE.load(Ordering::Acquire) {
        1 => Source::Devicetree,
        2 => Source::Acpi,
        _ => Source::None,
    }
}

/// ITS control-frame physical base in use.
pub fn its_base_pa() -> u64 {
    ITS_PA.load(Ordering::Acquire)
}

/// ITS doorbell physical address (`GITS_TRANSLATER`). Devices write the
/// EventID here.
#[inline]
pub fn doorbell_pa() -> u64 {
    its_base_pa() + reg::GITS_TRANSLATER
}

/// PCI requester ID (`bus << 8 | devfn`) on `segment` → ITS DeviceID,
/// through the IORT root-complex mappings or the DT `msi-map`, identity
/// when firmware describes none. `None` when a `msi-map` excludes the RID.
pub fn pci_device_id(segment: u16, rid: u16) -> Option<u32> {
    match FIRMWARE.lock().as_ref() {
        Some(fw) => fw.pci_device_id(segment, rid),
        None => Some(rid as u32),
    }
}

/// LPI INTID for logical vector `v` (the dispatch path keys on the low
/// byte of the INTID, and `LPI_BASE` is a multiple of 256).
pub const fn lpi_for_vector(v: u8) -> u32 {
    LPI_BASE + v as u32
}

// ── Bring-up ────────────────────────────────────────────────────────

fn its_regs() -> Regs {
    Regs {
        va: ITS_VA.load(Ordering::Acquire),
    }
}

/// Find and map the BSP's redistributor RD_base frame.
fn bsp_redistributor() -> Result<(u64, usize, u64), ItsError> {
    let aff = narf_arch::aarch64::cpu::mpidr_aff();
    let (regions, stride, gicc) = match FIRMWARE.lock().as_ref() {
        Some(fw) if !fw.rd_regions.is_empty() || !fw.gicc_rd.is_empty() => {
            (fw.rd_regions.clone(), fw.rd_stride, fw.gicc_rd.clone())
        }
        _ => {
            let _ = writeln!(
                narf_console::Writer,
                "  its: no firmware redistributor description; assuming QEMU virt @ {QEMU_GICR_BASE:#x}"
            );
            (
                Vec::from([(QEMU_GICR_BASE, QEMU_GICR_LEN)]),
                None,
                Vec::new(),
            )
        }
    };
    let read_typer = |pa: u64| -> Option<u64> {
        // SAFETY: firmware-described redistributor frame; GICR_TYPER is RO.
        let m = unsafe {
            narf_memory::ioremap::ioremap(pa, 0x1000, narf_memory::ioremap::MmioAttrs::Device)
        }
        .ok()?;
        let v = Regs {
            va: m.va() as usize,
        }
        .read64(reg::GICR_TYPER);
        // SAFETY: mapping made just above, not shared.
        unsafe { narf_memory::ioremap::iounmap(m) };
        Some(v)
    };
    let mut hit = None;
    for &(aff_gicc, base) in &gicc {
        if aff_gicc == aff {
            hit = read_typer(base).map(|t| (base, t));
            break;
        }
    }
    if hit.is_none() {
        for &region in &regions {
            if let Some(h) = its_fw::find_rd_frame(region, stride, aff, read_typer) {
                hit = Some(h);
                break;
            }
        }
    }
    let (rd_pa, typer) = hit.ok_or(ItsError::NoRedistributor)?;
    let va = if rd_pa == QEMU_GICR_BASE && EARLY_GICR_VA.load(Ordering::Acquire) != 0 {
        EARLY_GICR_VA.load(Ordering::Acquire)
    } else {
        map(rd_pa, reg::GICR_STRIDE_V3).ok_or(ItsError::NoMemory)?
    };
    Ok((rd_pa, va, typer))
}

/// Bring up the ITS on the BSP. Idempotent; later calls return `Ok(())`.
///
/// # Safety
/// - GICv3 distributor + CPU 0 redistributor must be enabled
///   (`gic::init_bsp` ran first) and the MMU handoff done (`ioremap`).
/// - `narf_memory::init_from_map` must have run.
/// - [`discover_firmware`] should have run; without it the QEMU virt
///   layout is assumed.
pub unsafe fn init_bsp() -> Result<(), ItsError> {
    if INIT_DONE.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut state = STATE.lock();
    if state.is_some() {
        return Ok(());
    }
    if source() == Source::None {
        let _ = writeln!(
            narf_console::Writer,
            "  its: no firmware ITS description; assuming QEMU virt @ {QEMU_ITS_BASE:#x}"
        );
    }

    // ── 1. ITS frame ──────────────────────────────────────────────
    let its_pa = its_base_pa();
    let early = ITS_VA.load(Ordering::Acquire);
    if early == 0 || its_pa != QEMU_ITS_BASE {
        let va = map(its_pa, reg::ITS_FRAME_LEN).ok_or(ItsError::NoMemory)?;
        ITS_VA.store(va, Ordering::Release);
    }
    let mut regs = its_regs();
    let typer = ItsTyper(regs.read64(reg::GITS_TYPER));
    if !typer.physical() {
        return Err(ItsError::Setup(SetupError::NoLpis));
    }

    // Firmware may hand over an enabled ITS (kexec / UEFI): disable and
    // wait for quiescence before touching the BASERs (`its_force_quiescent`).
    let ctlr = regs.read32(reg::GITS_CTLR);
    if ctlr & itsc::GITS_CTLR_ENABLE != 0 {
        regs.write32(reg::GITS_CTLR, ctlr & !itsc::GITS_CTLR_ENABLE);
    }
    let quiet = narf_scheduler::responsive_spin_until(
        || regs.read32(reg::GITS_CTLR) & itsc::GITS_CTLR_QUIESCENT != 0,
        narf_time::Deadline::after_ms(1000),
    );
    if !quiet {
        return Err(ItsError::InitTimeout);
    }

    // ── 2. Device / collection tables ─────────────────────────────
    let tables = itsc::alloc_tables(
        &mut regs,
        typer,
        narf_lib::percpu::MAX_CPUS as u64,
        &mut FrameMem,
    )?;
    let device_ids = tables.device_ids(typer);

    // ── 3. Command queue ──────────────────────────────────────────
    let cmdq_pa = FrameMem
        .alloc(itsc::CMD_QUEUE_BYTES, itsc::SZ_64K)
        .ok_or(ItsError::NoMemory)?;
    let (_, cmd_flush) = itsc::setup_cbaser(&mut regs, cmdq_pa, itsc::CMD_QUEUE_BYTES)?;
    if cmd_flush {
        FrameMem.flush(cmdq_pa, itsc::CMD_QUEUE_BYTES);
    }
    regs.write64(reg::GITS_CWRITER, 0);

    // ── 4. Enable the ITS ─────────────────────────────────────────
    let ctlr = regs.read32(reg::GITS_CTLR);
    regs.write32(reg::GITS_CTLR, ctlr | itsc::GITS_CTLR_ENABLE);

    // ── 5. LPI property / pending tables on the BSP redistributor ─
    let (rd_pa, rd_va, gicr_typer) = bsp_redistributor()?;
    let id_bits = itsc::lpi_id_bits(super::gic::gicd_typer(), NUM_LPIS)
        .ok_or(ItsError::Setup(SetupError::NoLpis))?;
    let prop_bytes = itsc::prop_table_bytes(id_bits);
    let prop_pa = FrameMem
        .alloc(prop_bytes, itsc::SZ_4K)
        .ok_or(ItsError::NoMemory)?;
    // SAFETY: freshly allocated property table, direct-mapped.
    unsafe {
        core::ptr::write_bytes(
            PhysAddr::new(prop_pa).kernel_mut_ptr::<u8>(),
            itsc::lpi_prop_byte(false),
            prop_bytes as usize,
        )
    };
    FrameMem.flush(prop_pa, prop_bytes);
    let pend_bytes = itsc::pend_table_bytes(id_bits);
    let pend_pa = FrameMem
        .alloc(pend_bytes, itsc::PEND_ALIGN)
        .ok_or(ItsError::NoMemory)?;
    FrameMem.flush(pend_pa, pend_bytes);
    let lpis = itsc::init_lpis(&mut Regs { va: rd_va }, prop_pa, pend_pa, id_bits)?;
    let rd_target = itsc::rd_target(typer, rd_pa, gicr_typer);

    *CMD_LOCK.lock() = Some(CmdState {
        queue: CmdQueue::new(itsc::CMD_QUEUE_BYTES),
        va: PhysAddr::new(cmdq_pa).kernel_mut_ptr::<u8>() as usize,
        flush: cmd_flush,
    });
    *state = Some(Its {
        typer,
        tables,
        device_ids,
        id_bits,
        prop_pa,
        prop_bytes,
        prop_flush: lpis.prop_flush,
        pend_pa,
        rd_pa,
        rd_va,
        rd_target,
        devices: Vec::new(),
    });

    // ── 6. MAPC collection 0 → BSP, INVALL, SYNC (its_cpu_init_collection)
    submit(&[
        itsc::cmd_mapc(0, rd_target, true),
        itsc::cmd_invall(0),
        itsc::cmd_sync(rd_target),
    ])?;
    INIT_DONE.store(true, Ordering::Release);
    Ok(())
}

fn submit(cmds: &[Cmd]) -> Result<(), ItsError> {
    let mut g = CMD_LOCK.lock();
    let st = g.as_ref().ok_or(ItsError::NotInitialised)?;
    let mut queue = st.queue;
    let r = itsc::submit(
        &mut CmdPort {
            regs: its_regs(),
            st,
        },
        &mut queue,
        cmds,
    );
    // The software write pointer follows what was posted even on error.
    if let Some(st) = g.as_mut() {
        st.queue = queue;
    }
    r.map_err(ItsError::from)
}

// ── Devices and events ──────────────────────────────────────────────

/// What a device's ITT looks like.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub device_id: u32,
    pub itt_pa: u64,
    pub itt_bytes: u64,
    pub nr_ites: u32,
}

fn set_lpi_config(its: &Its, lpi: u32, enabled: bool) {
    let off = (lpi - LPI_BASE) as u64;
    let p = PhysAddr::new(its.prop_pa + off).kernel_mut_ptr::<u8>();
    // SAFETY: `lpi` is range-checked by callers; property table is ours.
    unsafe { core::ptr::write_volatile(p, itsc::lpi_prop_byte(enabled)) };
    if its.prop_flush {
        // SAFETY: one byte of the direct-mapped property table.
        unsafe { narf_arch::aarch64::cache::clean_inval_to_poc(p as usize, 1) };
    } else {
        narf_arch::aarch64::cache::dsb_ishst();
    }
}

/// Find or create `device_id`'s ITT (`its_create_device`), returning its
/// index and whether it is new (so MAPD still has to be sent).
fn device_slot(its: &mut Its, device_id: u32, nvecs: u32) -> Result<(usize, bool), ItsError> {
    if device_id as u64 >= its.device_ids {
        return Err(ItsError::DeviceIdOutOfRange);
    }
    if let Some(i) = its.devices.iter().position(|d| d.id == device_id) {
        if its.devices[i].nr_ites < nvecs {
            return Err(ItsError::IttTooSmall);
        }
        return Ok((i, false));
    }
    let plan = itsc::plan_itt(nvecs, its.typer);
    let pa = FrameMem
        .alloc(plan.bytes, itsc::ITS_ITT_ALIGN)
        .ok_or(ItsError::NoMemory)?;
    // Linux flushes every new ITT: the ITS may not snoop it.
    FrameMem.flush(pa, plan.bytes);
    its.devices.push(Device {
        id: device_id,
        itt_pa: pa,
        itt_order: order_for(plan.bytes),
        nr_ites: plan.nr_ites,
        events: Vec::new(),
    });
    Ok((its.devices.len() - 1, true))
}

fn mapd(d: &Device, valid: bool) -> Cmd {
    itsc::cmd_mapd(d.id, d.itt_pa, (d.nr_ites.ilog2() - 1) as u8, valid)
}

fn info(d: &Device, typer: ItsTyper) -> DeviceInfo {
    DeviceInfo {
        device_id: d.id,
        itt_pa: d.itt_pa,
        itt_bytes: itsc::plan_itt(d.nr_ites, typer).bytes,
        nr_ites: d.nr_ites,
    }
}

/// Allocate an ITT for `nvecs` events and bind it with MAPD + SYNC.
/// Returns the existing ITT when the device is already known and large
/// enough.
///
/// # Safety
/// `init_bsp` succeeded; `device_id` names the caller's device as the ITS
/// sees it (see [`pci_device_id`]).
pub unsafe fn create_device(device_id: u32, nvecs: u32) -> Result<DeviceInfo, ItsError> {
    let mut g = STATE.lock();
    let its = g.as_mut().ok_or(ItsError::NotInitialised)?;
    let (i, new) = device_slot(its, device_id, nvecs.max(1))?;
    if new {
        submit(&[mapd(&its.devices[i], true), itsc::cmd_sync(its.rd_target)])?;
    }
    Ok(info(&its.devices[i], its.typer))
}

/// Map `(device_id, event_id)` → `lpi_intid` on `collection` (MAPD on
/// first use with a [`DEFAULT_DEVICE_EVENTS`]-entry ITT, then MAPTI, enable
/// bit, INV, SYNC). Re-mapping the same event moves it (DISCARD first).
/// Only collection 0 (the BSP) is mapped; any other collection is routed
/// there.
///
/// # Safety
/// `init_bsp` succeeded; `device_id` is the caller's device.
pub unsafe fn map_event(
    device_id: u32,
    event_id: u32,
    lpi_intid: u32,
    collection: u16,
) -> Result<(), ItsError> {
    let _ = collection;
    if !(LPI_BASE..LPI_BASE + NUM_LPIS).contains(&lpi_intid) {
        return Err(ItsError::LpiOutOfRange);
    }
    let mut g = STATE.lock();
    let its = g.as_mut().ok_or(ItsError::NotInitialised)?;
    let nvecs = DEFAULT_DEVICE_EVENTS.max(event_id.saturating_add(1));
    let (i, new) = match its.devices.iter().position(|d| d.id == device_id) {
        Some(i) => (i, false),
        None => device_slot(its, device_id, nvecs)?,
    };
    if event_id >= its.devices[i].nr_ites {
        return Err(ItsError::EventOutOfRange);
    }
    let prev = its.devices[i]
        .events
        .iter()
        .position(|&(e, _)| e == event_id);
    if let Some(p) = prev {
        if its.devices[i].events[p].1 == lpi_intid {
            return Ok(());
        }
    }
    set_lpi_config(its, lpi_intid, true);
    let target = its.rd_target;
    let d = &its.devices[i];
    let mut cmds: Vec<Cmd> = Vec::with_capacity(5);
    if new {
        cmds.push(mapd(d, true));
    }
    if prev.is_some() {
        cmds.push(itsc::cmd_discard(device_id, event_id));
    }
    cmds.push(itsc::cmd_mapti(device_id, event_id, lpi_intid, 0));
    cmds.push(itsc::cmd_inv(device_id, event_id));
    cmds.push(itsc::cmd_sync(target));
    submit(&cmds)?;
    let d = &mut its.devices[i];
    match prev {
        Some(p) => d.events[p].1 = lpi_intid,
        None => d.events.push((event_id, lpi_intid)),
    }
    Ok(())
}

/// DISCARD one event and disable its LPI.
///
/// # Safety
/// The device must no longer raise `event_id` (or tolerate its loss).
pub unsafe fn unmap_event(device_id: u32, event_id: u32) -> Result<(), ItsError> {
    let mut g = STATE.lock();
    let its = g.as_mut().ok_or(ItsError::NotInitialised)?;
    let i = its
        .devices
        .iter()
        .position(|d| d.id == device_id)
        .ok_or(ItsError::UnknownDevice)?;
    let p = its.devices[i]
        .events
        .iter()
        .position(|&(e, _)| e == event_id)
        .ok_or(ItsError::UnknownDevice)?;
    let (_, lpi) = its.devices[i].events[p];
    submit(&[
        itsc::cmd_discard(device_id, event_id),
        itsc::cmd_sync(its.rd_target),
    ])?;
    its.devices[i].events.swap_remove(p);
    if !its
        .devices
        .iter()
        .any(|d| d.events.iter().any(|&(_, l)| l == lpi))
    {
        set_lpi_config(its, lpi, false);
    }
    Ok(())
}

/// DISCARD every event, unmap the ITT (MAPD V=0), SYNC, then free it.
///
/// # Safety
/// The device must be quiesced (no further MSI writes).
pub unsafe fn free_device(device_id: u32) -> Result<(), ItsError> {
    let mut g = STATE.lock();
    let its = g.as_mut().ok_or(ItsError::NotInitialised)?;
    let i = its
        .devices
        .iter()
        .position(|d| d.id == device_id)
        .ok_or(ItsError::UnknownDevice)?;
    let mut cmds: Vec<Cmd> = its.devices[i]
        .events
        .iter()
        .map(|&(e, _)| itsc::cmd_discard(device_id, e))
        .collect();
    cmds.push(mapd(&its.devices[i], false));
    cmds.push(itsc::cmd_sync(its.rd_target));
    submit(&cmds)?;
    let d = its.devices.swap_remove(i);
    for &(_, lpi) in &d.events {
        if !its
            .devices
            .iter()
            .any(|o| o.events.iter().any(|&(_, l)| l == lpi))
        {
            set_lpi_config(its, lpi, false);
        }
    }
    narf_memory::frame::free_pages(
        narf_memory::PhysFrame::new(PhysAddr::new(d.itt_pa)),
        d.itt_order,
    );
    Ok(())
}

/// Raise `(device_id, event_id)` from software (ITS `INT` + SYNC). Used by
/// the kernel tests to exercise the full ITS → redistributor path without
/// a device.
///
/// # Safety
/// The event must be mapped and its vector handled.
#[doc(hidden)]
pub unsafe fn __test_inject(device_id: u32, event_id: u32) -> Result<(), ItsError> {
    let g = STATE.lock();
    let its = g.as_ref().ok_or(ItsError::NotInitialised)?;
    submit(&[
        itsc::cmd_int(device_id, event_id),
        itsc::cmd_sync(its.rd_target),
    ])
}

/// Snapshot of the programmed ITS, for diagnostics and tests.
#[derive(Copy, Clone, Debug)]
pub struct Status {
    pub source: Source,
    pub its_pa: u64,
    pub typer: ItsTyper,
    pub tables: Tables,
    pub device_ids: u64,
    pub id_bits: u32,
    pub prop_pa: u64,
    pub prop_bytes: u64,
    pub pend_pa: u64,
    pub rd_pa: u64,
    pub propbaser: u64,
    pub pendbaser: u64,
}

pub fn status() -> Option<Status> {
    let g = STATE.lock();
    let its = g.as_ref()?;
    let mut rd = Regs { va: its.rd_va };
    Some(Status {
        source: source(),
        its_pa: its_base_pa(),
        typer: its.typer,
        tables: its.tables,
        device_ids: its.device_ids,
        id_bits: its.id_bits,
        prop_pa: its.prop_pa,
        prop_bytes: its.prop_bytes,
        pend_pa: its.pend_pa,
        rd_pa: its.rd_pa,
        propbaser: rd.read64(reg::GICR_PROPBASER),
        pendbaser: rd.read64(reg::GICR_PENDBASER),
    })
}

/// Property byte for `lpi` (priority | group | enable).
pub fn lpi_config(lpi: u32) -> Option<u8> {
    let g = STATE.lock();
    let its = g.as_ref()?;
    if !(LPI_BASE..LPI_BASE + NUM_LPIS).contains(&lpi) {
        return None;
    }
    let p = PhysAddr::new(its.prop_pa + (lpi - LPI_BASE) as u64).kernel_ptr::<u8>();
    // SAFETY: inside the live property table.
    Some(unsafe { core::ptr::read_volatile(p) })
}

/// ITT of a known device.
pub fn device_info(device_id: u32) -> Option<DeviceInfo> {
    let g = STATE.lock();
    let its = g.as_ref()?;
    its.devices
        .iter()
        .find(|d| d.id == device_id)
        .map(|d| info(d, its.typer))
}

impl fmt::Display for ItsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ItsError::NoMemory => f.write_str("ITS: out of frames"),
            ItsError::InitTimeout => f.write_str("ITS: register did not settle"),
            ItsError::CmdTimeout => f.write_str("ITS: command queue did not drain"),
            ItsError::CmdStalled { offset } => {
                write!(f, "ITS: command queue stalled at offset {offset:#x}")
            }
            ItsError::NotInitialised => f.write_str("ITS: init_bsp not called"),
            ItsError::Setup(e) => write!(f, "ITS: setup refused: {e:?}"),
            ItsError::NoRedistributor => f.write_str("ITS: no redistributor for the BSP"),
            ItsError::DeviceIdOutOfRange => f.write_str("ITS: DeviceID out of range"),
            ItsError::EventOutOfRange => f.write_str("ITS: EventID beyond ITT"),
            ItsError::LpiOutOfRange => f.write_str("ITS: LPI out of range"),
            ItsError::UnknownDevice => f.write_str("ITS: unknown device or event"),
            ItsError::IttTooSmall => f.write_str("ITS: existing ITT too small"),
        }
    }
}
