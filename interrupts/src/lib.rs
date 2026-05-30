//! narf-interrupts — IRQ routing.
//!
//! Spec: `interrupts/specification/spec.md`. Stage-2 subset: x2APIC
//! enable + LAPIC-timer periodic IRQ + EOI. Fallbacks to xAPIC on
//! pre-x2APIC parts land when we care about non-Sapphire-Rapids
//! hardware (post-Stage-2).
//!
//! All IRQ vectors are in 32..=255 by convention; 0..=31 are reserved
//! for CPU exceptions. See `frame/x86_64/idt.rs` for the IDT install
//! and `frame/x86_64/trap.rs` for the Rust-side dispatch: vector < 32
//! → exception, vector >= 32 → IRQ (EOI after handler).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod dispatch;
pub mod vector;
pub mod wait;

mod tests;

pub use dispatch::{
    add_nmi_handler, disable_irq, enable_irq, fire_count, fire_count_on_cpu,
    install as install_handler, install_handler_named, installed_handler_names, is_masked,
    nmi_fire_count, nmi_spurious_count, on_irq, on_nmi, remove_handler, remove_nmi_handler,
    snapshot_counters, spurious_count, synchronize_irq, wakes_invoked, HandlerEntry,
    IrqCounterSnapshot, IrqStatus, NmiHandler, NmiHandlerId, SyncHandler, NUM_VECTORS,
    PERCPU_FIRES_MAX,
};
pub use wait::{wait_for_irq, wait_for_irq_until, WaitForIrq};

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as current;

/// Typical IRQ-vector assignments.
pub const VECTOR_TIMER: u8 = 32;
/// Cross-CPU TLB-shootdown IPI. Sender writes a target VA to a
/// per-CPU shootdown slot then signals via x2APIC ICR all-but-self;
/// the handler runs INVLPG and bumps an ack counter.
pub const VECTOR_TLB_SHOOTDOWN: u8 = 0xF0;
/// LAPIC error vector — programmed into LVT_ERROR. Reading
/// IA32_X2APIC_ESR after writing 0 to it (Intel SDM Vol 3
/// §11.5.3) reports which error bits latched. Diagnostic
/// only — the kernel doesn't recover from APIC errors.
pub const VECTOR_APIC_ERROR: u8 = 0xFE;
pub const VECTOR_SPURIOUS: u8 = 0xFF;

/// Send end-of-interrupt to the LAPIC.
///
/// # Safety
/// Must be called from an IRQ handler, with the APIC initialised.
#[cfg(target_arch = "x86_64")]
pub unsafe fn eoi() {
    // SAFETY: platform contract; x86_64 backend writes to the LAPIC EOI
    // register. Must be invoked exactly once per IRQ handler dispatch,
    // else the LAPIC will stall further interrupts on the same level.
    unsafe {
        current::eoi();
    }
}

/// Stub: aarch64 GIC EOI lands with the GICv3 skeleton.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn eoi() {}

/// Wire `narf-memory`'s `tlb_shootdown::shootdown` IPI fan-out hook
/// to the per-arch IPI primitive. Called once by the boot path
/// after SMP comes up; on a single-CPU boot it's still safe but
/// reduces to a no-op (the hook itself short-circuits when only
/// one CPU is online).
pub fn install_tlb_shootdown_bridge() {
    narf_memory::tlb_shootdown::set_ipi_fanout(ipi_fanout_bridge);
}

#[cfg(target_arch = "x86_64")]
fn ipi_fanout_bridge(req: narf_memory::tlb_shootdown::ShootdownRequest) {
    if narf_lib::smp::cpu_count() <= 1 {
        return;
    }
    match (req.tag, req.addr, req.size) {
        // Tag + VA + size: tag-aware range shootdown. Peers
        // INVPCID(tag, va) per page. Intel SDM Vol 2 INVPCID type 0.
        (Some(tag), Some(va), Some(size)) => {
            let pages = (size + 0xFFF) / 0x1000;
            // SAFETY: x2APIC online post-boot; vector installed.
            unsafe {
                x86_64::ipi::shoot_range(va, pages.max(1), tag);
            }
        }
        // Tag + VA single-page.
        (Some(tag), Some(va), None) => {
            // SAFETY: same.
            unsafe {
                x86_64::ipi::shoot_va(va, tag);
            }
        }
        // Tag-only (full per-tag flush) — real per-tag broadcast.
        // Peers run `INVPCID(1, tag)` (single-context invalidation,
        // Intel SDM Vol 3 §4.10.4.1). Matches the spec line in
        // `memory/specification/asid-pcid-isolation.md` §4 about
        // tag-scoped fan-out.
        (Some(tag), None, _) => {
            // SAFETY: x2APIC online; vector installed.
            unsafe {
                x86_64::ipi::shoot_tag_only(tag);
            }
        }
        // No tag — full TLB flush. The handler skips invalidation
        // when both tag and VA are zero; we still broadcast the
        // IPI so every peer's ack counter advances and the
        // shootdown_count atomic in narf-memory observes delivery.
        // Peers will pick up the generation bump on their next
        // page-table switch.
        (None, _, _) => {
            // SAFETY: x2APIC online; broadcast to all-but-self.
            unsafe {
                x86_64::apic::wrmsr_icr(
                    0xC0u64 << 12     // dest shorthand all-excluding-self
                  | (1 << 14)         // level=assert
                  | (VECTOR_TLB_SHOOTDOWN as u64),
                );
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn ipi_fanout_bridge(_req: narf_memory::tlb_shootdown::ShootdownRequest) {
    if narf_lib::smp::cpu_count() <= 1 {
        return;
    }
    // SAFETY: GIC is up post-boot; SGI_TLB_SHOOTDOWN is the
    // reserved vector for this purpose.
    unsafe {
        aarch64::sgi::broadcast_others(aarch64::sgi::SGI_TLB_SHOOTDOWN);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn ipi_fanout_bridge(_req: narf_memory::tlb_shootdown::ShootdownRequest) {}

/// Per-arch CPU "target id" used in MSI / MSI-X routing fields.
///
/// On x86_64 this is the local x2APIC ID (read from MSR 0x802),
/// which is what an MSI-X table entry's upper-address field
/// expects. On aarch64 it is the GICv3 collection / affinity
/// triple in a form suitable for `GITS_TYPER` routing — until
/// the ITS skeleton is wired we return 0 so PCIe MSI-X paths
/// at least compile and pass structural smokes.
///
/// # Safety
/// On x86_64 the x2APIC must be online (init runs at boot, so
/// this is satisfied for any post-`init` driver).
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn current_cpu_target_id() -> u32 {
    // SAFETY: x2APIC online, MSR 0x802 is read-only.
    unsafe { current::apic::apic_id() }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub unsafe fn current_cpu_target_id() -> u32 {
    0
}
