//! aarch64 system-register helpers.
//!
//! Every accessor carries the `compiler_fence(SeqCst)` pair discipline
//! from `arch/` §4 to defeat fat-LTO reorder across privileged MSR /
//! MRS instructions.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

macro_rules! pmu_read {
    ($name:ident, $reg:literal) => {
        #[doc = concat!("Read `", $reg, "` for the current CPU.")]
        ///
        /// # Safety
        /// Requires EL1 and an implemented PMUv3 system-register interface.
        #[inline]
        pub unsafe fn $name() -> u64 {
            compiler_fence(Ordering::SeqCst);
            let value: u64;
            // SAFETY: caller establishes EL1 + PMUv3 presence.
            unsafe {
                asm!(concat!("mrs {value}, ", $reg), value = out(reg) value,
                    options(nostack, preserves_flags));
            }
            compiler_fence(Ordering::SeqCst);
            value
        }
    };
}

macro_rules! pmu_write {
    ($name:ident, $reg:literal) => {
        #[doc = concat!("Write `", $reg, "` for the current CPU.")]
        ///
        /// # Safety
        /// Requires EL1 and an implemented PMUv3 system-register interface.
        #[inline]
        pub unsafe fn $name(value: u64) {
            compiler_fence(Ordering::SeqCst);
            // SAFETY: caller establishes EL1 + PMUv3 presence.
            unsafe {
                asm!(concat!("msr ", $reg, ", {value}"), "isb", value = in(reg) value,
                    options(nostack, preserves_flags));
            }
            compiler_fence(Ordering::SeqCst);
        }
    };
}

pmu_read!(read_id_aa64dfr0_el1, "id_aa64dfr0_el1");
pmu_read!(read_pmcr_el0, "pmcr_el0");
pmu_read!(read_pmccntr_el0, "pmccntr_el0");
pmu_read!(read_pmccfiltr_el0, "pmccfiltr_el0");
pmu_read!(read_pmovsclr_el0, "pmovsclr_el0");
pmu_read!(read_pmcntenset_el0, "pmcntenset_el0");
pmu_read!(read_pmintenset_el1, "pmintenset_el1");
pmu_read!(read_pmxevcntr_el0, "pmxevcntr_el0");
pmu_read!(read_pmxevtyper_el0, "pmxevtyper_el0");
pmu_read!(read_pmceid0_el0, "pmceid0_el0");
pmu_read!(read_pmceid1_el0, "pmceid1_el0");
pmu_write!(write_pmcr_el0, "pmcr_el0");
pmu_write!(write_pmccntr_el0, "pmccntr_el0");
pmu_write!(write_pmccfiltr_el0, "pmccfiltr_el0");
pmu_write!(write_pmselr_el0, "pmselr_el0");
pmu_write!(write_pmxevtyper_el0, "pmxevtyper_el0");
pmu_write!(write_pmxevcntr_el0, "pmxevcntr_el0");
pmu_write!(write_pmcntenset_el0, "pmcntenset_el0");
pmu_write!(write_pmcntenclr_el0, "pmcntenclr_el0");
pmu_write!(write_pmintenset_el1, "pmintenset_el1");
pmu_write!(write_pmintenclr_el1, "pmintenclr_el1");
pmu_write!(write_pmovsclr_el0, "pmovsclr_el0");

/// Write `VBAR_EL1` — the EL1 exception vector table base address.
/// Takes effect immediately; subsequent exceptions dispatch through
/// `addr`.
///
/// # Safety
/// `addr` must be 2 KiB-aligned and point at a 16-entry AArch64
/// exception vector table as laid out by `frame/aarch64/vec.S`.
#[inline]
pub unsafe fn write_vbar_el1(addr: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR VBAR_EL1 at EL1 is legal.
    unsafe {
        asm!("msr vbar_el1, {v}", v = in(reg) addr,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_SRE_EL1` — GICv3 system-register enable.
///
/// # Safety
/// Requires GICv3 sysreg interface exposed (check via CPUID).
#[inline]
pub unsafe fn write_icc_sre_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR ICC_SRE_EL1 at EL1 is legal when GICv3 is present.
    unsafe {
        asm!("msr icc_sre_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_PMR_EL1` — priority mask for CPU-interface IRQs.
///
/// # Safety
/// Requires `ICC_SRE_EL1.SRE = 1` to have been set first.
#[inline]
pub unsafe fn write_icc_pmr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR legal once SRE is enabled.
    unsafe {
        asm!("msr icc_pmr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_IGRPEN1_EL1` — enable Group 1 IRQs.
///
/// # Safety
/// Requires SRE.
#[inline]
pub unsafe fn write_icc_igrpen1_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: MSR legal once SRE is enabled.
    unsafe {
        asm!("msr icc_igrpen1_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read `ICC_IAR1_EL1` — acknowledge the highest-priority pending Group
/// 1 IRQ. Returns the INTID (low 24 bits).
///
/// # Safety
/// Must be called from an IRQ handler; reading clears the IRQ from the
/// CPU interface.
#[inline]
pub unsafe fn read_icc_iar1_el1() -> u64 {
    compiler_fence(Ordering::SeqCst);
    let v: u64;
    // SAFETY: MRS ICC_IAR1_EL1 is the documented handler entry path.
    unsafe {
        asm!("mrs {v}, icc_iar1_el1", v = out(reg) v,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write `ICC_EOIR1_EL1` — end-of-interrupt for Group 1. Pass the
/// value previously read from `ICC_IAR1_EL1`.
///
/// # Safety
/// Must match a prior IAR read, from inside an IRQ handler.
#[inline]
pub unsafe fn write_icc_eoir1_el1(iar: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: EOI to Group 1; matching IAR.
    unsafe {
        asm!("msr icc_eoir1_el1, {v}", v = in(reg) iar,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `ICC_SGI1R_EL1` — generate a Group 1 software-generated
/// interrupt to one or more CPUs. The encoding (Arm IHI 0069H §11.7):
/// bits[3:0]   = INTID (0..15)
/// bits[15:8]  = target list (which CPUs in the cluster)
/// bits[23:16] = Aff1
/// bits[33:32] = Aff2
/// bits[55:48] = Aff3
/// bit  40     = Range Selector (0 here = use the encoded affinity)
/// bit  31     = IRM  (1 = broadcast all-but-self)
///
/// # Safety
/// GICv3 system-register interface must be enabled (`ICC_SRE_EL1`).
#[inline]
pub unsafe fn write_icc_sgi1r_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller-asserted SGI dispatch.
    unsafe {
        asm!("msr icc_sgi1r_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `CNTP_TVAL_EL0` — sets the physical timer's next-fire count
/// as a delta from now. When written, the timer re-arms.
///
/// # Safety
/// Always legal at EL1.
#[inline]
pub unsafe fn write_cntp_tval_el0(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: CNTP_TVAL_EL0 write is always legal at EL1 / EL0 (when
    // CNTKCTL_EL1 grants EL0 access).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!("msr cntp_tval_el0, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `CNTP_CTL_EL0` — physical-timer control.
///   bit 0: ENABLE
///   bit 1: IMASK (1 = masked)
///   bit 2: ISTATUS (read-only, set when the timer has fired)
///
/// # Safety
/// Always legal at EL1.
#[inline]
pub unsafe fn write_cntp_ctl_el0(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: see write_cntp_tval_el0.
    unsafe {
        asm!("msr cntp_ctl_el0, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read the saved `ESR_EL1` (exception syndrome) after an exception.
/// Used by synchronous-exception handlers.
///
/// # Safety
/// Always legal at EL1.
#[inline]
pub unsafe fn read_esr_el1() -> u64 {
    let v: u64;
    // SAFETY: MRS ESR_EL1 at EL1 is always legal.
    unsafe {
        asm!("mrs {v}, esr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `FAR_EL1` (fault address register).
///
/// # Safety
/// Issues a privileged `MRS` on `FAR_EL1`; the caller must execute at
/// EL1 (or a level where the register is accessible).
#[inline]
pub unsafe fn read_far_el1() -> u64 {
    let v: u64;
    // SAFETY: MRS FAR_EL1 at EL1 is always legal.
    unsafe {
        asm!("mrs {v}, far_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `ELR_EL1` — exception-link register (saved PC at exception entry).
///
/// # Safety
/// Issues a privileged `MRS` on `ELR_EL1`; the caller must execute at
/// EL1 (or a level where the register is accessible).
#[inline]
pub unsafe fn read_elr_el1() -> u64 {
    let v: u64;
    // SAFETY: MRS ELR_EL1 at EL1 is always legal.
    unsafe {
        asm!("mrs {v}, elr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read `SCTLR_EL1` — System Control Register.
///
/// # Safety
/// Issues a privileged `MRS` on `SCTLR_EL1`; the caller must execute at
/// EL1 (or a level where the register is accessible).
#[inline]
pub unsafe fn read_sctlr_el1() -> u64 {
    let v: u64;
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("mrs {v}, sctlr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `SCTLR_EL1`.
///
/// # Safety
/// Issues a privileged `MSR` on `SCTLR_EL1`; the caller must ensure the
/// written value is valid for the register (MMU/cache/alignment control)
/// and that the write is permitted at the current exception level.
#[inline]
pub unsafe fn write_sctlr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr sctlr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `TCR_EL1` — Translation Control Register.
///
/// # Safety
/// Issues a privileged `MSR` on `TCR_EL1`; the caller must ensure the
/// written value is a valid translation-control configuration and that
/// the write is permitted at the current exception level.
#[inline]
pub unsafe fn write_tcr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr tcr_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read `TCR_EL1`.
///
/// # Safety
/// Issues a privileged `MRS` on `TCR_EL1`; the caller must execute at
/// EL1 (or a level where the register is accessible).
#[inline]
pub unsafe fn read_tcr_el1() -> u64 {
    let v: u64;
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("mrs {v}, tcr_el1", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `GCR_EL1` — Tag Control Register. Uses the raw
/// `S<op0>_<op1>_C<crn>_C<crm>_<op2>` encoding (Op0=3, Op1=0, CRn=1,
/// CRm=0, Op2=6) because the `gcr_el1` mnemonic requires the `+mte`
/// target feature which the bare `aarch64-unknown-none` target
/// doesn't enable by default.
///
/// # Safety
/// On CPUs without MTE (ID_AA64PFR1_EL1.MTE == 0), this raises #UD.
/// Callers must gate on `Features::probe().mte > 0`.
#[inline]
pub unsafe fn write_gcr_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller confirmed MTE is present.
    unsafe {
        asm!("msr s3_0_c1_c0_6, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read `GCR_EL1`.
///
/// # Safety
/// Same as `write_gcr_el1`: requires MTE support.
#[inline]
pub unsafe fn read_gcr_el1() -> u64 {
    let v: u64;
    // SAFETY: caller confirmed MTE is present.
    unsafe {
        asm!("mrs {v}, s3_0_c1_c0_6", v = out(reg) v,
             options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `MAIR_EL1` — Memory Attribute Indirection Register.
///
/// # Safety
/// Issues a privileged `MSR` on `MAIR_EL1`; the caller must ensure the
/// written memory-attribute encoding is valid and that the write is
/// permitted at the current exception level.
#[inline]
pub unsafe fn write_mair_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr mair_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Read the complete `TTBR0_EL1` value, including its ASID field.
///
/// # Safety
/// Issues a privileged `MRS` on `TTBR0_EL1`; the caller must execute at EL1.
#[inline]
pub unsafe fn read_ttbr0_el1() -> u64 {
    compiler_fence(Ordering::SeqCst);
    let value: u64;
    // SAFETY: caller establishes EL1 and `value` is the sole output.
    unsafe {
        asm!(
            "mrs {value}, ttbr0_el1",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    value
}

/// Write the complete `TTBR0_EL1` value, including its ASID field.
///
/// # Safety
/// Issues a privileged `MSR` on `TTBR0_EL1`; the caller must ensure the
/// value points at a live translation-table base owned for the encoded ASID,
/// and that the write is permitted at the current exception level.
#[inline]
pub unsafe fn write_ttbr0_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller establishes EL1 and a live `(root, ASID)` pair. The DSB
    // completes prior table writes before the root changes; the ISB makes the
    // new translation context effective before a later instruction/access.
    unsafe {
        asm!(
            "dsb ish",
            "msr ttbr0_el1, {value}",
            "isb",
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Write `TTBR1_EL1` — Translation Table Base Register 1.
///
/// # Safety
/// Issues a privileged `MSR` on `TTBR1_EL1`; the caller must ensure the
/// value points at a valid translation-table base and that the write is
/// permitted at the current exception level.
#[inline]
pub unsafe fn write_ttbr1_el1(value: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: Always legal at EL1.
    unsafe {
        asm!("msr ttbr1_el1, {v}", v = in(reg) value,
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate entire TLB for EL1.
///
/// # Safety
/// Issues a privileged `TLBI VMALLE1`; the caller must execute at EL1.
/// Stale translations may be used until this completes, so callers must
/// sequence it correctly with page-table edits.
#[inline]
pub unsafe fn tlb_flush_all() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: TLBI VMALLE1 is legal at EL1.
    unsafe {
        asm!(
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            options(nostack, preserves_flags)
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate TLB by virtual address for EL1.
///
/// # Safety
/// Issues a privileged `TLBI VAAE1`; the caller must execute at EL1 and
/// pass a virtual address whose stale translations are safe to drop.
#[inline]
pub unsafe fn tlb_flush_page(virt_addr: u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: TLBI VAAE1 is legal at EL1. Shifts VA by 12 as required.
    unsafe {
        asm!("tlbi vaae1, {v}", "dsb nsh", "isb",
             v = in(reg) (virt_addr >> 12),
             options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// Instruction Synchronization Barrier.
///
/// # Safety
/// Issues a privileged `ISB`; the caller must execute at EL1 (or a level
/// where the barrier is permitted).
#[inline]
pub unsafe fn isb() {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: ISB is always legal.
    unsafe {
        asm!("isb", options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

// ── ASID-scoped TLB invalidation ───────────────────────────────────
//
// Spec: `memory/specification/asid-pcid-isolation.md` §3.2.
//
// `TLBI ASIDE1IS` operand layout: bits[63:48] = ASID, rest reserved.
// `TLBI VAE1IS` operand layout: bits[63:48] = ASID, bits[43:0] = VA[55:12].

/// Invalidate every TLB entry tagged with `asid` across all CPUs in
/// the inner-shareable domain.
///
/// # Safety
/// EL1; `asid` ≤ the architectural max (8 or 16 bits).
#[inline]
pub unsafe fn tlbi_asid_inner_shareable(asid: u16) {
    compiler_fence(Ordering::SeqCst);
    let operand = (asid as u64) << 48;
    // SAFETY: TLBI ASIDE1IS is legal at EL1.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi aside1is, {v}",
            "dsb ish",
            "isb",
            v = in(reg) operand,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Invalidate the TLB entry for `va` tagged with `asid` across the
/// inner-shareable domain.
///
/// # Safety
/// EL1; `va` is a canonical aarch64 virtual address (low half).
#[inline]
pub unsafe fn tlbi_va_asid_inner_shareable(asid: u16, va: u64) {
    compiler_fence(Ordering::SeqCst);
    // VAE1IS encoding: bits[43:0] = VA[55:12], bits[63:48] = ASID.
    let operand = ((asid as u64) << 48) | ((va >> 12) & 0x0000_FFFF_FFFF_FFFF);
    // SAFETY: TLBI VAE1IS is legal at EL1.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vae1is, {v}",
            "dsb ish",
            "isb",
            v = in(reg) operand,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Number of ASID bits the CPU implements (8 or 16). Read from
/// `ID_AA64MMFR0_EL1.ASIDBits` (bits[7:4]); 0 = 8-bit ASIDs,
/// 2 = 16-bit ASIDs.
#[inline]
pub fn asid_bits() -> u8 {
    let v: u64;
    // SAFETY: ID_AA64MMFR0_EL1 is always readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack));
    }
    if (v >> 4) & 0xF == 2 {
        16
    } else {
        8
    }
}

/// Read the current TTBR0_EL1 ASID field (bits[63:48]).
#[inline]
pub fn read_ttbr0_asid() -> u16 {
    let v: u64;
    // SAFETY: TTBR0_EL1 is always readable at EL1.
    unsafe {
        asm!("mrs {}, ttbr0_el1", out(reg) v, options(nomem, nostack));
    }
    ((v >> 48) & 0xFFFF) as u16
}

/// Write `TTBR0_EL1` with `(root_phys, asid)`. The root phys is
/// kept in BADDR (bits[47:1]); the ASID lives in bits[63:48].
///
/// # Safety
/// EL1; `root_phys` is a valid translation-table base; `asid` ≤
/// the architectural max.
#[inline]
pub unsafe fn write_ttbr0_el1_with_asid(root_phys: u64, asid: u16) {
    compiler_fence(Ordering::SeqCst);
    let v = (root_phys & 0x0000_FFFF_FFFF_FFFE) | ((asid as u64) << 48);
    // SAFETY: caller-asserted EL1 + valid root.
    unsafe {
        asm!(
            "msr ttbr0_el1, {v}",
            "dsb ish",
            "isb",
            v = in(reg) v,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}
