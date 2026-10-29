//! Arm GIC bring-up: GICv3 (QEMU virt, SC7280) and GICv2 (QEMU
//! `virt,gic-version=2`, Qualcomm IPQ8074 / IPQ6018 / IPQ5018
//! `qcom,msm-qgic2`, `arm,gic-400`).
//!
//! The version and register windows come from the devicetree
//! ([`probe`], via [`crate::gic_dt::detect`]); with no devicetree GIC
//! node and a GICv3 system-register interface present, the historical
//! QEMU virt GICv3 bases are used, so v3 boots behave exactly as before.
//!
//! | piece          | GICv3                              | GICv2                         |
//! |----------------|------------------------------------|-------------------------------|
//! | distributor    | MMIO `GICD`                        | MMIO `GICD`                   |
//! | SGI/PPI config | per-CPU redistributor `SGI_base`   | banked `GICD` registers       |
//! | CPU interface  | `ICC_*_EL1` system registers       | MMIO `GICC` (banked per CPU)  |
//! | SPI routing    | `GICD_IROUTER` (affinity)          | `GICD_ITARGETSR` (CPU mask)   |
//! | SGIs           | `ICC_SGI1R_EL1`                    | `GICD_SGIR`                   |
//! | ack / EOI      | `ICC_IAR1_EL1` / `ICC_EOIR1_EL1`   | `GICC_IAR` / `GICC_EOIR`      |
//!
//! The backend is chosen once, by [`probe`] on the BSP before any IRQ is
//! unmasked, and published in [`is_v2`]; the trap path
//! ([`super::ack_irq`] / [`super::eoi_for`]) branches on that one static.
//! Every MMIO access goes through `narf_arch::aarch64::mmio`, whose
//! accessors carry `compiler_fence(SeqCst)` on both sides (AGENTS.md
//! invariant #4).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use narf_arch::aarch64::mmio::{read_u32, write_u32, write_u8};
use narf_arch::aarch64::sysreg;

pub use crate::gic_dt::{GicDescription, GicDetectError, GicVersion, MmioWindow};

/// QEMU virt GICv3 distributor MMIO base (fallback when no DT node).
const QEMU_GICD_BASE: usize = 0x0800_0000;
/// Distributor register frame size (GICv3 IHI0069H: 64 KiB).
const QEMU_GICD_LEN: usize = 0x1_0000;
/// QEMU virt GICv3 CPU-0 redistributor MMIO base.
const QEMU_GICR_BASE: usize = 0x080A_0000;
/// Per-CPU redistributor stride: RD_base + SGI_base, 64 KiB each
/// (GICv3). GICv4 parts publish `redistributor-stride` instead.
const GICR_STRIDE_V3: usize = 0x2_0000;
/// The GICv2 CPU interface is 8 KiB (`GICC_DIR` at 0x1000); only the
/// first page is used (EOImode 0), so a 4 KiB `reg` window suffices.
const GICC_MAP_MIN: usize = 0x1000;

// ── Discovered layout ──────────────────────────────────────────────
//
// Written once by `probe` (BSP, IRQs masked, before `init_bsp` and before
// any AP is started), read everywhere after. Defaults are the QEMU virt
// GICv3 layout so a caller that never probes keeps the old behaviour.

static DIST_PA: AtomicUsize = AtomicUsize::new(QEMU_GICD_BASE);
static DIST_LEN: AtomicUsize = AtomicUsize::new(QEMU_GICD_LEN);
/// GICv2: the `GICC` base. GICv3: the first redistributor frame.
static CPU_PA: AtomicUsize = AtomicUsize::new(QEMU_GICR_BASE);
static CPU_LEN: AtomicUsize = AtomicUsize::new(GICC_MAP_MIN);
static REDIST_STRIDE: AtomicUsize = AtomicUsize::new(GICR_STRIDE_V3);
/// `true` once [`probe`] selected the GICv2 backend. The single static
/// the trap path branches on.
static V2: AtomicBool = AtomicBool::new(false);
/// 0 = not probed, else 2 or 3.
static VERSION: AtomicU8 = AtomicU8::new(0);

/// Mapped kernel VA of the distributor window, resolved by [`map_gicd`].
static GICD_VA: AtomicUsize = AtomicUsize::new(0);
/// GICv2 only: mapped kernel VA of the (banked) CPU interface.
static GICC_VA: AtomicUsize = AtomicUsize::new(0);
/// GICv3 only: mapped kernel VA of each CPU's redistributor frame,
/// resolved by [`map_gicr`] on the CPU that owns it.
static GICR_VA: [AtomicUsize; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; narf_lib::percpu::MAX_CPUS];

/// GICv2 only: each logical CPU's CPU-interface bit (`GICD_ITARGETSR`
/// / `GICD_SGIR` target list), read from the banked `ITARGETSR0..7` by
/// that CPU in [`init_ap`] / [`init_bsp`]. 0 = not yet known.
static V2_CPU_MASK: [AtomicU8; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU8::new(0) }; narf_lib::percpu::MAX_CPUS];
/// GICv2 only: the MPIDR affinity of the CPU owning `V2_CPU_MASK[i]`.
static V2_CPU_AFF: [AtomicU32; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU32::new(u32::MAX) }; narf_lib::percpu::MAX_CPUS];

/// `true` when the GICv2 backend is active. Boot-time constant after
/// [`probe`]; `Relaxed` is enough because it is stored before the first
/// IRQ is unmasked on the BSP and before any AP is released, and every
/// AP re-reads it with `Acquire` in [`init_ap`] before its own unmask.
#[inline(always)]
pub fn is_v2() -> bool {
    V2.load(Ordering::Relaxed)
}

/// The backend [`probe`] selected, `None` before probing.
pub fn version() -> Option<GicVersion> {
    match VERSION.load(Ordering::Acquire) {
        2 => Some(GicVersion::V2),
        3 => Some(GicVersion::V3),
        _ => None,
    }
}

// ── Discovery ──────────────────────────────────────────────────────

/// Where the layout [`probe`] installed came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeSource {
    /// A devicetree GIC node.
    Devicetree,
    /// No DT GIC node; QEMU virt GICv3 constants (the pre-discovery
    /// behaviour), used only when the GICv3 sysreg interface exists.
    QemuVirtDefault,
}

/// Why [`probe`] left IRQs off.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The devicetree describes a GIC but not usably (`MissingReg`).
    /// Guessing addresses for described-but-broken hardware is refused.
    Devicetree(GicDetectError),
    /// The devicetree says GICv3 but `ID_AA64PFR0_EL1.GIC` reports no
    /// system-register CPU interface.
    NoSysregInterface,
    /// No devicetree GIC node and no GICv3 sysreg interface to justify
    /// the QEMU default.
    NotFound,
}

/// Largest devicetree blob [`probe`] will read (matches the boot parser).
const MAX_DTB_SIZE: usize = 2 * 1024 * 1024;

/// Select the GIC backend and register windows. BSP only, IRQs masked,
/// exactly once, before [`init_bsp`].
///
/// `gicv3_sysreg` is `Features::probe().gicv3_sysreg`.
///
/// # Safety
/// `dtb_phys`, when `Some`, must point at a live flattened devicetree
/// reachable through the identity map / direct map.
pub unsafe fn probe(
    dtb_phys: Option<u64>,
    gicv3_sysreg: bool,
) -> Result<(GicDescription, ProbeSource), ProbeError> {
    // SAFETY: caller contract.
    let blob =
        dtb_phys.and_then(|p| unsafe { narf_firmware_fdt::discover(p as usize, MAX_DTB_SIZE) });
    let found = blob.map(crate::gic_dt::detect);
    let desc = match found {
        Some(Ok(d)) => {
            if d.version == GicVersion::V3 && !gicv3_sysreg {
                return Err(ProbeError::NoSysregInterface);
            }
            install(&d);
            return Ok((d, ProbeSource::Devicetree));
        }
        Some(Err(e @ GicDetectError::MissingReg(_))) => return Err(ProbeError::Devicetree(e)),
        // No blob, a bad blob, or no GIC node in it.
        Some(Err(_)) | None => {
            if !gicv3_sysreg {
                return Err(ProbeError::NotFound);
            }
            GicDescription {
                version: GicVersion::V3,
                dist: MmioWindow {
                    base: QEMU_GICD_BASE as u64,
                    len: QEMU_GICD_LEN as u64,
                },
                cpu: MmioWindow {
                    base: QEMU_GICR_BASE as u64,
                    len: GICR_STRIDE_V3 as u64,
                },
                redist_stride: None,
            }
        }
    };
    install(&desc);
    Ok((desc, ProbeSource::QemuVirtDefault))
}

fn install(d: &GicDescription) {
    DIST_PA.store(d.dist.base as usize, Ordering::Relaxed);
    DIST_LEN.store(d.dist.len as usize, Ordering::Relaxed);
    CPU_PA.store(d.cpu.base as usize, Ordering::Relaxed);
    CPU_LEN.store(
        (d.cpu.len as usize).clamp(GICC_MAP_MIN, 2 * GICC_MAP_MIN),
        Ordering::Relaxed,
    );
    REDIST_STRIDE.store(
        d.redist_stride.map_or(GICR_STRIDE_V3, |s| s as usize),
        Ordering::Relaxed,
    );
    let v2 = d.version == GicVersion::V2;
    V2.store(v2, Ordering::SeqCst);
    VERSION.store(if v2 { 2 } else { 3 }, Ordering::Release);
}

// ── Mapping ────────────────────────────────────────────────────────

fn ioremap_device(pa: usize, len: usize) -> Option<usize> {
    // SAFETY: a firmware-described (or QEMU-architectural) GIC register
    // window, owned by this module.
    unsafe {
        narf_memory::ioremap::ioremap(
            pa as u64,
            len as u64,
            narf_memory::ioremap::MmioAttrs::Device,
        )
    }
    .ok()
    .map(|m| m.va() as usize)
}

/// Map the distributor window (and, on GICv2, the banked CPU interface,
/// which every CPU reaches at the same address). Called by the BSP.
///
/// The GIC is MMIO and the kernel no longer keeps a Device block over the
/// low 1 GiB, so these registers have to be mapped like any other device.
/// `ioremap` places them in TTBR1 (shared by every address space) as
/// Device-nGnRE: untagged, so MTE domain checks never apply and the trap
/// path can reach `GICC` from `DomainId::FRAME` whatever task it
/// interrupted.
fn map_gicd() {
    if GICD_VA.load(Ordering::Acquire) == 0 {
        if let Some(va) = ioremap_device(
            DIST_PA.load(Ordering::Relaxed),
            DIST_LEN.load(Ordering::Relaxed),
        ) {
            GICD_VA.store(va, Ordering::Release);
        }
    }
    if is_v2() && GICC_VA.load(Ordering::Acquire) == 0 {
        if let Some(va) = ioremap_device(
            CPU_PA.load(Ordering::Relaxed),
            CPU_LEN.load(Ordering::Relaxed),
        ) {
            GICC_VA.store(va, Ordering::Release);
        }
    }
}

/// Map `cpu_index`'s redistributor frame (GICv3 only). Called on that CPU,
/// or for it by the BSP before it starts; mapping per CPU keeps us from
/// mapping frames for CPUs the machine does not implement.
fn map_gicr(cpu_index: u32) {
    let slot = cpu_index as usize;
    if is_v2() || slot >= narf_lib::percpu::MAX_CPUS || GICR_VA[slot].load(Ordering::Acquire) != 0 {
        return;
    }
    let stride = REDIST_STRIDE.load(Ordering::Relaxed);
    let phys = CPU_PA.load(Ordering::Relaxed) + slot * stride;
    if let Some(va) = ioremap_device(phys, stride) {
        GICR_VA[slot].store(va, Ordering::Release);
    }
}

/// Base to reach the distributor through: the mapped VA once one exists,
/// the physical base before that.
///
/// GIC init runs before the MMU handoff, so `ioremap` is not available yet
/// and the boot tables' Device block is what makes the physical base work.
/// [`remap_mmio`] switches this over at the handoff, before that block is
/// dropped — the same shape as `console::remap_to_virtual`.
#[inline]
fn gicd_base() -> usize {
    match GICD_VA.load(Ordering::Acquire) {
        0 => DIST_PA.load(Ordering::Relaxed),
        va => va,
    }
}

/// GICv2 CPU interface base: mapped VA once one exists, else physical.
/// See [`gicd_base`].
#[inline(always)]
fn gicc_base() -> usize {
    match GICC_VA.load(Ordering::Acquire) {
        0 => CPU_PA.load(Ordering::Relaxed),
        va => va,
    }
}

/// Base to reach `cpu_index`'s redistributor frame through (GICv3): the
/// mapped VA once one exists, the physical base before that. See
/// [`gicd_base`].
#[inline]
pub fn gicr_base(cpu_index: u32) -> usize {
    let slot = cpu_index as usize;
    let phys = CPU_PA.load(Ordering::Relaxed) + slot * REDIST_STRIDE.load(Ordering::Relaxed);
    if slot >= narf_lib::percpu::MAX_CPUS {
        return phys;
    }
    match GICR_VA[slot].load(Ordering::Acquire) {
        0 => phys,
        va => va,
    }
}

/// Move the GIC off its physical bases and onto `ioremap` windows.
///
/// Must run after `init_mmu` (so `ioremap` works) and before the boot
/// identity window is dropped (so the physical fallback still functions if a
/// mapping fails). Maps the distributor (+ GICv2 CPU interface) and, on
/// GICv3, `cpu_index`'s redistributor; the BSP maps each AP's before
/// starting it.
pub fn remap_mmio(cpu_index: u32) {
    map_gicd();
    map_gicr(cpu_index);
}

/// Raw `GICD_TYPER` (ITLinesNumber [4:0] on both versions; GICv3 adds
/// IDbits [23:19] and LPIS bit 17, which the ITS sizes its tables from).
pub fn gicd_typer() -> u32 {
    // SAFETY: distributor frame mapped by `init_bsp` / `remap_mmio`;
    // GICD_TYPER is read-only.
    unsafe { read_u32((gicd_base() + 0x0004) as *mut u32) }
}

// ── Register map ───────────────────────────────────────────────────

// Distributor (GICv2 IHI0048B §4.3, GICv3 IHI0069H §12.9).
const GICD_CTLR: usize = 0x0000;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_ISPENDR: usize = 0x0200;
const GICD_ICPENDR: usize = 0x0280;
const GICD_ICACTIVER: usize = 0x0380;
const GICD_IPRIORITYR: usize = 0x0400;
/// GICv2 only (RES0 / ignored under GICv3 affinity routing).
const GICD_ITARGETSR: usize = 0x0800;
const GICD_ICFGR: usize = 0x0C00;
/// GICv2 only: software-generated interrupt register.
const GICD_SGIR: usize = 0x0F00;
/// GICv3 only.
const GICD_IROUTER: usize = 0x6000;

// GICv2 CPU interface (IHI0048B §4.4).
const GICC_CTLR: usize = 0x0000;
const GICC_PMR: usize = 0x0004;
const GICC_BPR: usize = 0x0008;
const GICC_IAR: usize = 0x000C;
const GICC_EOIR: usize = 0x0010;
/// `GICC_CTLR` bypass-disable bits Linux preserves (`GICC_DIS_BYPASS_MASK`).
const GICC_DIS_BYPASS_MASK: u32 = 0x1e0;

// SGI/PPI bank: same offsets in the GICv3 redistributor `SGI_base` frame
// and the GICv2 banked distributor registers.
const PRIV_IGROUPR0: usize = 0x0080;
const PRIV_ISENABLER0: usize = 0x0100;
const PRIV_ICENABLER0: usize = 0x0180;
const PRIV_ICACTIVER0: usize = 0x0380;
const PRIV_IPRIORITYR: usize = 0x0400;
const PRIV_ICFGR1: usize = 0x0C04;
// Redistributor (GICv3).
const GICR_WAKER: usize = 0x0014;
const GICR_SGI_OFF: usize = 0x1_0000;

/// First SPI INTID; devicetree `<GIC_SPI n ..>` is INTID `32 + n`.
pub const SPI_BASE: u32 = 32;
/// Highest SPI INTID the architecture allows (1020..1023 are special).
pub const SPI_MAX: u32 = 1019;
/// Priority given to every configured interrupt (timer PPI, SGIs,
/// SPIs); below the PMR mask of 0xFF. Survives GICv2 parts that
/// implement only 4 or 5 priority bits.
const IRQ_PRIORITY: u8 = 0xA0;

/// Base of the SGI/PPI configuration bank for `cpu_index`: the GICv3
/// redistributor's `SGI_base`, or the (per-CPU banked) GICv2 distributor.
#[inline]
fn private_bank(cpu_index: u32) -> usize {
    if is_v2() {
        gicd_base()
    } else {
        gicr_base(cpu_index) + GICR_SGI_OFF
    }
}

// ── SPIs ───────────────────────────────────────────────────────────

/// Trigger mode of a shared peripheral interrupt (`GICD_ICFGR`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpiTrigger {
    /// `IRQ_TYPE_LEVEL_HIGH`.
    Level,
    /// `IRQ_TYPE_EDGE_RISING`.
    Edge,
}

/// Why an SPI could not be configured.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpiError {
    /// Not an SPI INTID, or above `GICD_TYPER.ITLinesNumber`.
    OutOfRange(u32),
}

/// Number of INTIDs the distributor implements: `32 * (ITLinesNumber + 1)`,
/// capped at 1020. Same `GICD_TYPER` field on GICv2 and GICv3.
pub fn spi_limit() -> u32 {
    ((gicd_typer() & 0x1f) + 1)
        .saturating_mul(32)
        .min(SPI_MAX + 1)
}

fn spi_check(intid: u32) -> Result<(), SpiError> {
    if !(SPI_BASE..=SPI_MAX).contains(&intid) || intid >= spi_limit() {
        return Err(SpiError::OutOfRange(intid));
    }
    Ok(())
}

/// Dispatch-table slot the aarch64 trap uses for `intid` (its low byte;
/// `frame/` passes `intid & 0xFF` to `on_irq`).
pub const fn spi_vector(intid: u32) -> u8 {
    (intid & 0xff) as u8
}

/// Configure SPI `intid` for delivery to the calling CPU: disable, clear
/// pending, set trigger and priority, route, then enable.
///
/// Routing: GICv3 puts the SPI in Group 1 NS and writes `GICD_IROUTER` =
/// this CPU's affinity (ARE_NS is on). GICv2 writes this CPU's interface
/// bit into `GICD_ITARGETSR` and leaves the group as firmware set it
/// (Group 1 for a non-secure kernel under TrustZone, the only group on a
/// GIC without the Security Extensions) — as Linux `irq-gic.c` does.
pub fn configure_spi(intid: u32, trigger: SpiTrigger) -> Result<(), SpiError> {
    spi_check(intid)?;
    let base = gicd_base();
    let word = (intid / 32) as usize * 4;
    let bit = 1u32 << (intid % 32);
    // SAFETY: distributor window mapped by `init_bsp` / `remap_mmio`;
    // every offset is inside the 4 KiB (v2) / 64 KiB (v3) frame for an
    // INTID < 1020 (IROUTER only on v3).
    unsafe {
        write_u32((base + GICD_ICENABLER + word) as *mut u32, bit);
        write_u32((base + GICD_ICPENDR + word) as *mut u32, bit);
        write_u8(
            (base + GICD_IPRIORITYR + intid as usize) as *mut u8,
            IRQ_PRIORITY,
        );
        let cfg = (base + GICD_ICFGR + (intid / 16) as usize * 4) as *mut u32;
        let shift = (intid % 16) * 2 + 1;
        let v = match trigger {
            SpiTrigger::Edge => read_u32(cfg) | (1 << shift),
            SpiTrigger::Level => read_u32(cfg) & !(1 << shift),
        };
        write_u32(cfg, v);
        if is_v2() {
            let mask = v2_this_cpu_mask();
            write_u8((base + GICD_ITARGETSR + intid as usize) as *mut u8, mask);
        } else {
            let grp = (base + GICD_IGROUPR + word) as *mut u32;
            write_u32(grp, read_u32(grp) | bit);
            let aff = narf_arch::aarch64::cpu::mpidr_aff() as u64;
            // IROUTER: Aff0 [7:0], Aff1 [15:8], Aff2 [23:16], Aff3 [39:32]; IRM = 0.
            let route = (aff & 0x00ff_ffff) | ((aff >> 24) << 32);
            let r = (base + GICD_IROUTER + intid as usize * 8) as *mut u32;
            write_u32(r, route as u32);
            write_u32(r.add(1), (route >> 32) as u32);
        }
        write_u32((base + GICD_ISENABLER + word) as *mut u32, bit);
    }
    Ok(())
}

/// `disable_irq` at the distributor (`GICD_ICENABLER`).
pub fn mask_spi(intid: u32) -> Result<(), SpiError> {
    spi_check(intid)?;
    // SAFETY: as in `configure_spi`.
    unsafe {
        write_u32(
            (gicd_base() + GICD_ICENABLER + (intid / 32) as usize * 4) as *mut u32,
            1 << (intid % 32),
        );
    }
    Ok(())
}

/// `enable_irq` at the distributor (`GICD_ISENABLER`).
pub fn unmask_spi(intid: u32) -> Result<(), SpiError> {
    spi_check(intid)?;
    // SAFETY: as in `configure_spi`.
    unsafe {
        write_u32(
            (gicd_base() + GICD_ISENABLER + (intid / 32) as usize * 4) as *mut u32,
            1 << (intid % 32),
        );
    }
    Ok(())
}

/// Software-pend SPI `intid` (`GICD_ISPENDR`): self-test and
/// diagnostics; the interrupt is then delivered like a device one.
pub fn pend_spi(intid: u32) -> Result<(), SpiError> {
    spi_check(intid)?;
    // SAFETY: as in `configure_spi`.
    unsafe {
        write_u32(
            (gicd_base() + GICD_ISPENDR + (intid / 32) as usize * 4) as *mut u32,
            1 << (intid % 32),
        );
    }
    Ok(())
}

// ── PMU PPI ────────────────────────────────────────────────────────

static PMU_PPI: AtomicU32 = AtomicU32::new(u32::MAX);

/// Install the firmware-discovered PMU PPI and enable it on this CPU.
///
/// APs subsequently enable the same PPI from `init_per_cpu`. The caller must
/// not substitute a platform default when firmware discovery fails.
pub fn configure_pmu_ppi(intid: u32) -> Result<(), ()> {
    if !(16..32).contains(&intid) {
        return Err(());
    }
    PMU_PPI.store(intid, Ordering::Release);
    // SAFETY: this only touches the current CPU's already-initialised
    // SGI/PPI bank; the BSP calls it after init_bsp.
    unsafe { enable_private_irq(narf_lib::percpu::current_cpu() as u32, intid) };
    Ok(())
}

pub fn pmu_ppi() -> Option<u32> {
    match PMU_PPI.load(Ordering::Acquire) {
        u32::MAX => None,
        intid => Some(intid),
    }
}

// ── Bring-up ───────────────────────────────────────────────────────

/// Initialise the distributor and the BSP's CPU interface, then enable
/// IRQ signalling (DAIF still masks them).
///
/// # Safety
/// - Must run on the BSP, exactly once, at EL1, after [`probe`] succeeded.
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_bsp() {
    map_gicd();
    // SAFETY: windows mapped above / by init_per_cpu; caller contract.
    unsafe {
        if is_v2() {
            init_distributor_v2();
        } else {
            init_distributor();
        }
        init_per_cpu(0);
    }
}

/// Per-CPU GIC init for an AP: CPU interface + SGI/PPI bank (+ GICv3
/// redistributor wake) + timer PPI.
///
/// # Safety
/// - Must run on the CPU whose `cpu_index` is passed (this is the
///   only place where IRQ delivery for that CPU gets enabled).
/// - The BSP's [`init_bsp`] must have completed.
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_ap(cpu_index: u32) {
    // Pair with `install`'s stores: this CPU's later Relaxed `is_v2`
    // reads in the trap path cannot observe an older value than this.
    let _ = V2.load(Ordering::Acquire);
    // SAFETY: caller-asserted per-CPU invariant.
    unsafe {
        init_per_cpu(cpu_index);
    }
}

/// GICv3 distributor-side init (CPU-shared). Only the BSP runs this.
unsafe fn init_distributor() {
    // GICD_CTLR: enable Group 1 NS (bit 1). ARE_NS (bit 4) for
    // affinity routing.
    // SAFETY: mapped MMIO.
    unsafe {
        write_u32((gicd_base() + GICD_CTLR) as *mut u32, (1 << 4) | (1 << 1));
    }
}

/// GICv2 distributor-side init, after Linux `gic_dist_init` /
/// `gic_dist_config`: disable forwarding, route every SPI to the boot
/// CPU, make them level / default priority, deactivate and disable them,
/// then re-enable forwarding. Only the BSP runs this.
unsafe fn init_distributor_v2() {
    let base = gicd_base();
    let n = spi_limit() as usize;
    let mask = u32::from(v2_read_cpu_mask()) * 0x0101_0101;
    // SAFETY: mapped GICv2 distributor; every offset below is inside the
    // 4 KiB frame for INTIDs < spi_limit() <= 1020.
    unsafe {
        write_u32((base + GICD_CTLR) as *mut u32, 0);
        for i in (32..n).step_by(4) {
            write_u32((base + GICD_ITARGETSR + i) as *mut u32, mask);
            write_u32(
                (base + GICD_IPRIORITYR + i) as *mut u32,
                u32::from(IRQ_PRIORITY) * 0x0101_0101,
            );
        }
        for i in (32..n).step_by(16) {
            write_u32((base + GICD_ICFGR + i / 4) as *mut u32, 0);
        }
        for i in (32..n).step_by(32) {
            write_u32((base + GICD_ICACTIVER + i / 8) as *mut u32, u32::MAX);
            write_u32((base + GICD_ICENABLER + i / 8) as *mut u32, u32::MAX);
        }
        // Bit 0: EnableGrp0 without the Security Extensions (QEMU virt),
        // EnableGrp1 in the non-secure view (IPQ under TrustZone).
        write_u32((base + GICD_CTLR) as *mut u32, 1);
    }
}

/// This CPU's GICv2 interface bit, from the banked, read-only
/// `GICD_ITARGETSR0..7` (Linux `gic_get_cpumask`). 0 if the GIC reports
/// none (uniprocessor implementations may RAZ).
fn v2_read_cpu_mask() -> u8 {
    let base = gicd_base();
    for i in (0..32).step_by(4) {
        // SAFETY: banked SGI/PPI target registers, read-only.
        let mut m = unsafe { read_u32((base + GICD_ITARGETSR + i) as *mut u32) };
        m |= m >> 16;
        m |= m >> 8;
        if m & 0xff != 0 {
            return m as u8;
        }
    }
    0
}

/// The calling CPU's GICv2 interface bit, falling back to a fresh read
/// before `init_per_cpu` recorded it, and to CPU interface 0 when the
/// GIC reports none.
fn v2_this_cpu_mask() -> u8 {
    let cpu = narf_lib::percpu::current_cpu();
    let m = V2_CPU_MASK
        .get(cpu)
        .map_or(0, |m| m.load(Ordering::Acquire));
    match m {
        0 => match v2_read_cpu_mask() {
            0 => 1,
            m => m,
        },
        m => m,
    }
}

/// GICv2 `GICD_SGIR` target list for the CPU with MPIDR affinity `aff`.
/// CPUs that have not run `init_per_cpu` yet are unknown; QEMU virt and
/// the IPQ parts number CPU interfaces by Aff0, which is the fallback.
pub(crate) fn v2_cpu_mask_for_aff(aff: u32) -> u8 {
    for (i, a) in V2_CPU_AFF.iter().enumerate() {
        if a.load(Ordering::Acquire) == aff {
            let m = V2_CPU_MASK[i].load(Ordering::Acquire);
            if m != 0 {
                return m;
            }
        }
    }
    match aff & 0xff {
        n @ 0..=7 => 1 << n,
        _ => 0,
    }
}

/// Write `GICD_SGIR`: `filter` 0 = `targets` list, 1 = all but self,
/// 2 = self only.
///
/// # Safety
/// GICv2 backend active and the distributor initialised.
pub(crate) unsafe fn v2_send_sgi(intid: u8, filter: u32, targets: u8) {
    // Normal-memory stores the receiver will read (shootdown cells,
    // membarrier flags) must be visible before it can take the SGI
    // (Linux `gic_ipi_send_mask`: dmb ishst).
    core::sync::atomic::fence(Ordering::SeqCst);
    let v = ((filter & 0x3) << 24) | (u32::from(targets) << 16) | u32::from(intid & 0xf);
    // SAFETY: caller contract; GICD_SGIR is write-only.
    unsafe { write_u32((gicd_base() + GICD_SGIR) as *mut u32, v) };
}

/// GICv2 acknowledge: read `GICC_IAR`. Bits [9:0] INTID, [12:10] source
/// CPU for SGIs; the whole value goes back to [`v2_eoi`].
///
/// # Safety
/// IRQ context on a CPU whose GICv2 CPU interface is initialised.
#[inline(always)]
pub(crate) unsafe fn v2_ack() -> u32 {
    // SAFETY: caller contract; `read_u32` is fenced (invariant #4).
    let iar = unsafe { read_u32((gicc_base() + GICC_IAR) as *mut u32) };
    if iar & 0x3ff < 16 {
        // Data the SGI sender published is read after the acknowledge
        // (Linux `gic_handle_irq`: smp_rmb for SGIs).
        core::sync::atomic::fence(Ordering::Acquire);
    }
    iar
}

/// GICv2 end of interrupt: write the `GICC_IAR` value back to `GICC_EOIR`
/// (EOImode 0: priority drop + deactivate).
///
/// # Safety
/// Must match a prior [`v2_ack`] on this CPU.
#[inline(always)]
pub(crate) unsafe fn v2_eoi(iar: u32) {
    // SAFETY: caller contract; `write_u32` is fenced (invariant #4).
    unsafe { write_u32((gicc_base() + GICC_EOIR) as *mut u32, iar) };
}

/// CPU-private init: CPU interface + the named CPU's SGI/PPI bank +
/// timer PPI (+ PMU PPI when firmware described one).
unsafe fn init_per_cpu(cpu_index: u32) {
    if is_v2() {
        // SAFETY: caller contract (owning CPU, IRQs masked).
        unsafe { init_per_cpu_v2(cpu_index) };
    } else {
        // SAFETY: caller contract; probe verified the sysreg interface.
        unsafe { init_per_cpu_v3(cpu_index) };
    }
    if let Some(intid) = pmu_ppi() {
        // SAFETY: same current-CPU initialisation window.
        unsafe { enable_private_irq(cpu_index, intid) };
    }
}

/// Enable mask for this CPU's private interrupts: every SGI + timer PPI.
const PRIVATE_ENABLE: u32 = (1u32 << super::TIMER_PPI) | 0x0000_FFFF;

unsafe fn init_per_cpu_v3(cpu_index: u32) {
    // Map this CPU's redistributor before touching it. Runs on the owning
    // CPU: the BSP for index 0, each AP for its own.
    map_gicr(cpu_index);
    // ─── CPU interface (system registers) ───────────────────────
    // SAFETY: GICv3 presence verified by probe.
    unsafe {
        sysreg::write_icc_sre_el1(1);
        sysreg::write_icc_pmr_el1(0xFF);
        sysreg::write_icc_igrpen1_el1(1);
    }

    // ─── Redistributor ────────────────────────────────────────
    let gicr = gicr_base(cpu_index);
    // Clear ProcessorSleep (bit 1 of GICR_WAKER). Then poll
    // ChildrenAsleep (bit 2) until 0.
    // SAFETY: mapped MMIO; gicr is this CPU's redistributor frame.
    unsafe {
        let waker = (gicr + GICR_WAKER) as *mut u32;
        let cur = read_u32(waker);
        write_u32(waker, cur & !(1 << 1));
        while read_u32(waker) & (1 << 2) != 0 {
            core::hint::spin_loop();
        }
    }

    let bank = gicr + GICR_SGI_OFF;
    // SAFETY: same MMIO window. SGIs + PPIs in Group 1 NS, priority
    // below the PMR mask for the timer PPI and every SGI, then enable.
    unsafe {
        write_u32((bank + PRIV_IGROUPR0) as *mut u32, 0xFFFF_FFFF);
        write_u8(
            (bank + PRIV_IPRIORITYR + super::TIMER_PPI as usize) as *mut u8,
            IRQ_PRIORITY,
        );
        for sgi in 0..16usize {
            write_u8((bank + PRIV_IPRIORITYR + sgi) as *mut u8, IRQ_PRIORITY);
        }
        write_u32((bank + PRIV_ISENABLER0) as *mut u32, PRIVATE_ENABLE);
    }
}

/// GICv2 per-CPU init, after Linux `gic_cpu_init` / `gic_cpu_config` /
/// `gic_cpu_if_up`.
unsafe fn init_per_cpu_v2(cpu_index: u32) {
    let mask = v2_read_cpu_mask();
    if let Some(slot) = V2_CPU_MASK.get(cpu_index as usize) {
        V2_CPU_AFF[cpu_index as usize]
            .store(narf_arch::aarch64::cpu::mpidr_aff(), Ordering::Release);
        slot.store(mask, Ordering::Release);
    }
    let bank = gicd_base();
    let cpu = gicc_base();
    // SAFETY: mapped GICv2 distributor (banked SGI/PPI registers are this
    // CPU's) and CPU interface; caller holds IRQs masked.
    unsafe {
        // Banked private interrupts: deactivate + disable everything,
        // default priority, then enable the SGIs and the timer PPI.
        write_u32((bank + PRIV_ICACTIVER0) as *mut u32, u32::MAX);
        write_u32((bank + PRIV_ICENABLER0) as *mut u32, u32::MAX);
        for i in (0..32usize).step_by(4) {
            write_u32(
                (bank + PRIV_IPRIORITYR + i) as *mut u32,
                u32::from(IRQ_PRIORITY) * 0x0101_0101,
            );
        }
        write_u32((bank + PRIV_ISENABLER0) as *mut u32, PRIVATE_ENABLE);
        // CPU interface: unmask all priorities, no preemption grouping,
        // keep firmware's bypass-disable bits, enable signalling.
        write_u32((cpu + GICC_PMR) as *mut u32, 0xFF);
        write_u32((cpu + GICC_BPR) as *mut u32, 0);
        let bypass = read_u32((cpu + GICC_CTLR) as *mut u32) & GICC_DIS_BYPASS_MASK;
        write_u32((cpu + GICC_CTLR) as *mut u32, bypass | 1);
    }
}

unsafe fn enable_private_irq(cpu_index: u32, intid: u32) {
    let bank = private_bank(cpu_index);
    // SAFETY: caller executes for this CPU's live SGI/PPI bank and intid
    // was validated as an SGI/PPI-bank interrupt.
    unsafe {
        // PMUv3 overflow is a level-sensitive PPI. PPI trigger state is
        // implementation-defined at reset, so explicitly clear the edge bit
        // before enabling instead of relying on QEMU or firmware defaults
        // (read-only on some GICv2 parts, where the write is ignored).
        let cfg_shift = (intid - 16) * 2;
        let cfg = (bank + PRIV_ICFGR1) as *mut u32;
        write_u32(cfg, read_u32(cfg) & !(0b10 << cfg_shift));
        write_u8(
            (bank + PRIV_IPRIORITYR + intid as usize) as *mut u8,
            IRQ_PRIORITY,
        );
        write_u32((bank + PRIV_ISENABLER0) as *mut u32, 1u32 << intid);
    }
}
