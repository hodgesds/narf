//! GICv3 initialisation for the BSP on QEMU virt.
//!
//! Hybrid access: the *distributor* uses MMIO at `0x0800_0000`; the
//! *redistributor* uses MMIO at `0x080A_0000` for CPU 0 on QEMU virt;
//! the *CPU interface* uses system registers (`ICC_*_EL1`).
//!
//! Stage-2 scope: bring the BSP into a state where the generic-timer
//! PPI (INTID 30) can deliver IRQs. SMP AP bring-up + SPI (shared
//! peripheral interrupt) routing are later waves.

use core::sync::atomic::{AtomicU32, Ordering};
use narf_arch::aarch64::mmio::{read_u32, write_u32};
use narf_arch::aarch64::sysreg;

/// QEMU virt GICv3 distributor MMIO base.
const GICD_BASE: usize = 0x0800_0000;
/// Distributor register frame size (GICv3 IHI0069H: 64 KiB).
const GICD_LEN: usize = 0x1_0000;
/// QEMU virt GICv3 CPU-0 redistributor MMIO base.
const GICR_BASE: usize = 0x080A_0000;
/// Per-CPU redistributor stride. GICv3 lays each CPU's RD frame
/// 128 KiB apart on QEMU virt.
const GICR_STRIDE: usize = 0x2_0000;

/// Mapped kernel VA of the distributor window, resolved by [`map_gicd`].
static GICD_VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Mapped kernel VA of each CPU's redistributor frame, resolved by
/// [`map_gicr`] on the CPU that owns it.
static GICR_VA: [core::sync::atomic::AtomicUsize; narf_lib::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; narf_lib::percpu::MAX_CPUS];

/// Map the distributor window. Called once, by the BSP.
///
/// The GIC is MMIO and the kernel no longer keeps a Device block over the
/// low 1 GiB, so these registers have to be mapped like any other device.
fn map_gicd() {
    if GICD_VA.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return;
    }
    // SAFETY: the architectural GICv3 distributor window, owned by us.
    if let Ok(m) = unsafe {
        narf_memory::ioremap::ioremap(
            GICD_BASE as u64,
            GICD_LEN as u64,
            narf_memory::ioremap::MmioAttrs::Device,
        )
    } {
        GICD_VA.store(m.va() as usize, core::sync::atomic::Ordering::Release);
    }
}

/// Map `cpu_index`'s redistributor frame. Called on that CPU, before any
/// redistributor access; mapping per CPU keeps us from mapping frames for
/// CPUs the machine does not implement.
fn map_gicr(cpu_index: u32) {
    let slot = cpu_index as usize;
    if slot >= narf_lib::percpu::MAX_CPUS
        || GICR_VA[slot].load(core::sync::atomic::Ordering::Acquire) != 0
    {
        return;
    }
    let phys = GICR_BASE + slot * GICR_STRIDE;
    // SAFETY: this CPU's architectural redistributor frame.
    if let Ok(m) = unsafe {
        narf_memory::ioremap::ioremap(
            phys as u64,
            GICR_STRIDE as u64,
            narf_memory::ioremap::MmioAttrs::Device,
        )
    } {
        GICR_VA[slot].store(m.va() as usize, core::sync::atomic::Ordering::Release);
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
    match GICD_VA.load(core::sync::atomic::Ordering::Acquire) {
        0 => GICD_BASE,
        va => va,
    }
}

/// Base to reach `cpu_index`'s redistributor frame through: the mapped VA
/// once one exists, the physical base before that. See [`gicd_base`].
#[inline]
pub fn gicr_base(cpu_index: u32) -> usize {
    let slot = cpu_index as usize;
    let phys = GICR_BASE + slot * GICR_STRIDE;
    if slot >= narf_lib::percpu::MAX_CPUS {
        return phys;
    }
    match GICR_VA[slot].load(core::sync::atomic::Ordering::Acquire) {
        0 => phys,
        va => va,
    }
}

/// Move the GIC off its physical bases and onto `ioremap` windows.
///
/// Must run after `init_mmu` (so `ioremap` works) and before the boot
/// identity window is dropped (so the physical fallback still functions if a
/// mapping fails). Maps the distributor and the calling CPU's redistributor;
/// each AP maps its own in `init_per_cpu`, which by then runs post-handoff.
pub fn remap_mmio(cpu_index: u32) {
    map_gicd();
    map_gicr(cpu_index);
}

// Distributor register offsets (SDM of GICv3: IHI0069H).
const GICD_CTLR: usize = 0x0000;

// Redistributor register offsets.
const GICR_WAKER: usize = 0x0014;
// SGI_base is at GICR_BASE + 0x1_0000.
const GICR_SGI_OFF: usize = 0x1_0000;
const GICR_IGROUPR0_OFF: usize = GICR_SGI_OFF + 0x0080;
const GICR_ISENABLER0_OFF: usize = GICR_SGI_OFF + 0x0100;
const GICR_IPRIORITYR0_OFF: usize = GICR_SGI_OFF + 0x0400;
const GICR_ICFGR1_OFF: usize = GICR_SGI_OFF + 0x0C04;
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
    // redistributor; the BSP calls it after init_bsp.
    unsafe { enable_private_irq(narf_lib::percpu::current_cpu() as u32, intid) };
    Ok(())
}

pub fn pmu_ppi() -> Option<u32> {
    match PMU_PPI.load(Ordering::Acquire) {
        u32::MAX => None,
        intid => Some(intid),
    }
}

/// Initialise the BSP CPU's GICv3 view + enable Group 1 IRQs.
///
/// # Safety
/// - Must run on the BSP, exactly once, at EL1.
/// - GICv3 system-register interface must be available
///   (CPUID: `Features::probe().gicv3_sysreg`).
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_bsp() {
    // SAFETY: BSP-only init does both the CPU-shared distributor
    // and CPU 0's redistributor + cpu interface.
    // SAFETY: Valid memory or trusted environment
    map_gicd();
    // SAFETY: windows mapped above / by init_per_cpu.
    unsafe {
        init_distributor();
        init_per_cpu(0);
    }
}

/// Per-CPU GICv3 init for an AP. Wakes its redistributor + sets up
/// the EL1 CPU interface + enables the timer PPI.
///
/// # Safety
/// - Must run on the CPU whose `cpu_index` is passed (this is the
///   only place where IRQ delivery for that CPU gets enabled).
/// - GICv3 system-register interface must be available.
/// - Interrupts must be disabled in DAIF at call time.
pub unsafe fn init_ap(cpu_index: u32) {
    // SAFETY: caller-asserted per-CPU invariant.
    unsafe {
        init_per_cpu(cpu_index);
    }
}

/// Distributor-side init (CPU-shared). Only the BSP runs this.
unsafe fn init_distributor() {
    // GICD_CTLR: enable Group 1 NS (bit 1). ARE_NS (bit 4) for
    // affinity routing.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        write_u32((gicd_base() + GICD_CTLR) as *mut u32, (1 << 4) | (1 << 1));
    }
}

/// CPU-private init: cpu interface (system registers) + the named
/// CPU's redistributor + timer PPI.
unsafe fn init_per_cpu(cpu_index: u32) {
    // Map this CPU's redistributor before touching it. Runs on the owning
    // CPU: the BSP for index 0, each AP for its own.
    map_gicr(cpu_index);
    // ─── CPU interface (system registers) ───────────────────────
    // SAFETY: GICv3 presence verified by caller.
    unsafe {
        sysreg::write_icc_sre_el1(1);
    }
    // SAFETY: SRE set above.
    unsafe {
        sysreg::write_icc_pmr_el1(0xFF);
    }
    // SAFETY: SRE set above.
    unsafe {
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

    // Put SGIs + PPIs in Group 1 NS.
    // SAFETY: same MMIO window.
    unsafe {
        write_u32((gicr + GICR_IGROUPR0_OFF) as *mut u32, 0xFFFF_FFFF);
    }

    // Set priority for the timer PPI (INTID 30) — byte-addressable.
    // SAFETY: same.
    unsafe {
        let prio = (gicr + GICR_IPRIORITYR0_OFF + 30) as *mut u8;
        core::ptr::write_volatile(prio, 0xA0);
    }

    // Enable the timer PPI + every SGI (INTID 0..15). SGIs are
    // already in Group 1 via IGROUPR0 above; ISENABLER0 must be
    // set per bit to actually deliver. Each SGI also needs a
    // priority below the PMR mask (0xFF) — we set 0xA0 like the
    // timer.
    // SAFETY: identity-mapped MMIO.
    unsafe {
        // Priority for SGIs 0..15.
        for sgi in 0..16u64 {
            let prio = (gicr + GICR_IPRIORITYR0_OFF + sgi as usize) as *mut u8;
            core::ptr::write_volatile(prio, 0xA0);
        }
        // Enable timer PPI + all SGIs.
        let mask = (1u32 << super::TIMER_PPI) | 0x0000_FFFF;
        write_u32((gicr + GICR_ISENABLER0_OFF) as *mut u32, mask);
    }
    if let Some(intid) = pmu_ppi() {
        // SAFETY: same current-CPU redistributor initialisation window.
        unsafe { enable_private_irq(cpu_index, intid) };
    }
}

unsafe fn enable_private_irq(cpu_index: u32, intid: u32) {
    let gicr = gicr_base(cpu_index);
    // SAFETY: caller executes for this CPU's live redistributor and intid was
    // validated as an SGI/PPI-bank interrupt.
    unsafe {
        // PMUv3 overflow is a level-sensitive PPI. PPI trigger state is
        // implementation-defined at reset, so explicitly clear the edge bit
        // before enabling instead of relying on QEMU or firmware defaults.
        let cfg_shift = (intid - 16) * 2;
        let cfg = (gicr + GICR_ICFGR1_OFF) as *mut u32;
        write_u32(cfg, read_u32(cfg) & !(0b10 << cfg_shift));
        let prio = (gicr + GICR_IPRIORITYR0_OFF + intid as usize) as *mut u8;
        core::ptr::write_volatile(prio, 0xA0);
        write_u32((gicr + GICR_ISENABLER0_OFF) as *mut u32, 1u32 << intid);
    }
}
