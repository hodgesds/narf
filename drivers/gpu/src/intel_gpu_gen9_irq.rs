//! Gen9 (Skylake / Kaby Lake / Coffee Lake) interrupt routing.
//!
//! The Gen9 display + GT interrupt model (`display/intel_display_irq.c`,
//! `gt/intel_gt_irq.c`, `i915_irq.c`, Linux 7.4-rc2), grounded
//! register-by-register — this is the §17 interrupt-routing item
//! (Lane 8). It is a *separate* block from the xe-era GT IRQ
//! registers in `intel_gpu_gt_irq.rs` (the 0x190000 block): Gen9
//! routes through the 0x44xxx master/DE/GT-bank registers, and
//! the xe module must not be assumed to extend.
//!
//! # Model
//!
//! - `GEN8_MASTER_IRQ` (0x44200) is the top-level gate: bit 31
//!   is the master enable, the low bits are the per-source
//!   pending flags (`GEN8_GT_*_IRQ` for the GT engines, the
//!   `GEN8_DE_PIPE_*`/`PORT`/`MISC`/`PCH` bits for display).
//!   The same address is `GEN11_DISPLAY_INT_CTL` on Gen11+ —
//!   the Gen11 HPD bit 21 in that register does not exist on
//!   Gen9 and is not modeled here.
//! - The DE block (0x44000 display summary, 0x44400 pipes,
//!   0x44440 port, 0x44460 misc, 0x444e0 PCU) and the four GT
//!   banks (0x44300 + 0x10 per bank) each carry the
//!   ISR/IMR/IIR/IER quartet. IIR is write-1-to-clear: the
//!   handler reads it, dispatches, and writes it back to ack.
//! - The PCH (SDE) split registers (0xc4004/08/0c) are owned
//!   by `intel_gpu_dp.rs` and are not duplicated here.
//!
//! # Sequences (Linux `gen2_irq_reset` / `gen2_irq_init` shapes)
//!
//! - Reset: IMR = all-ones + posting read, IER = 0, IIR =
//!   all-ones twice + posting reads.
//! - Post-install: IER = the enabled set, IMR = its complement
//!   (bank 2 — PM/RPS + GuC — stays IER 0 / IMR all-ones; its
//!   sources are enabled on demand).
//! - Top-level dispatch (`gen8_irq_handler`): master disable
//!   (write 0, read back the pending mask) → GT banks whose
//!   master bits are set → display handler for the remaining
//!   master bits → master enable (write the CONTROL bit).
//!
//! # The interrupt owner (`narf.intel.gen9_irq=1`, default off)
//!
//! [`Gen9IrqCore`] wires the primitives the way `i915_irq.c`'s
//! `gen8_irq_handler` and `intel_display_irq.c`'s
//! `gen8_de_irq_handler` do, delivered the way the Gen12 GT's
//! interrupts are (`intel_gpu_gt_irq`): MSI on x86, a hard
//! handler that only turns the master off and latches its
//! sources, and a task-context service pass that acknowledges
//! the GT banks, DE misc, the DE port, each pipe and the
//! SPT-class PCH, then turns the master on again. Hotplug
//! follows the display-14 and Gen12 monitors: the shared monitor
//! (`intel_gpu_dp::HpdMonitor`) keeps its pins, unmasks them for
//! this owner (`spt_hpd_irq_setup`, `bxt_hpd_irq_setup`), and
//! reads and acknowledges their IIR itself
//! (`gen8_read_and_ack_pch_irqs` + `spt_irq_handler`, Gen9 LP's
//! `bxt_hpd_irq_handler`); a trigger runs the external-output
//! pass. The execlists GT owner wakes on the vector, but its
//! completions stay proven by the CSB, never by an interrupt.
//! System sleep is `intel_irq_suspend` / `intel_irq_resume`: the
//! master off before the Gen9 display suspend owner and the DC
//! service need it off (Gen9 LP DC9), and on again after resume.
//!
//! Stricter than Linux, and why: the SPT-class SDE block stays
//! the monitor's (no `ibx_irq_postinstall`, only its owned pins
//! unmasked); the service pass reads display registers under a
//! Gen9 `DC_off` reference; pipes B/C are programmed only when
//! PW_2 is up at install or resume (no
//! `gen8_irq_power_well_post_enable`); vblank, flip-done and
//! underrun stay masked (no consumer asks for them).

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_pipes::Pipe;

// ── Master IRQ ──────────────────────────────────────────────────

/// `GEN8_MASTER_IRQ` (`include/drm/intel/intel_gmd_interrupt_regs.h`).
pub const GEN8_MASTER_IRQ: u64 = 0x44200;
/// Master enable — `GEN8_MASTER_IRQ_CONTROL` (bit 31).
pub const GEN8_MASTER_IRQ_CONTROL: u32 = 1 << 31;
/// `GEN8_PCU_IRQ` (bit 30).
pub const GEN8_PCU_IRQ: u32 = 1 << 30;
/// `GEN8_DE_PCH_IRQ` (bit 23).
pub const GEN8_DE_PCH_IRQ: u32 = 1 << 23;
/// `GEN8_DE_MISC_IRQ` (bit 22).
pub const GEN8_DE_MISC_IRQ: u32 = 1 << 22;
/// `GEN8_DE_PORT_IRQ` (bit 20).
pub const GEN8_DE_PORT_IRQ: u32 = 1 << 20;
/// `GEN8_DE_PIPE_C_IRQ` (bit 18).
pub const GEN8_DE_PIPE_C_IRQ: u32 = 1 << 18;
/// `GEN8_DE_PIPE_B_IRQ` (bit 17).
pub const GEN8_DE_PIPE_B_IRQ: u32 = 1 << 17;
/// `GEN8_DE_PIPE_A_IRQ` (bit 16).
pub const GEN8_DE_PIPE_A_IRQ: u32 = 1 << 16;
/// `GEN8_GT_VECS_IRQ` (bit 6).
pub const GEN8_GT_VECS_IRQ: u32 = 1 << 6;
/// `GEN8_GT_GUC_IRQ` (bit 5).
pub const GEN8_GT_GUC_IRQ: u32 = 1 << 5;
/// `GEN8_GT_PM_IRQ` (bit 4).
pub const GEN8_GT_PM_IRQ: u32 = 1 << 4;
/// `GEN8_GT_VCS1_IRQ` (bit 3).
pub const GEN8_GT_VCS1_IRQ: u32 = 1 << 3;
/// `GEN8_GT_VCS0_IRQ` (bit 2).
pub const GEN8_GT_VCS0_IRQ: u32 = 1 << 2;
/// `GEN8_GT_BCS_IRQ` (bit 1).
pub const GEN8_GT_BCS_IRQ: u32 = 1 << 1;
/// `GEN8_GT_RCS_IRQ` (bit 0).
pub const GEN8_GT_RCS_IRQ: u32 = 1 << 0;
/// `GEN8_GT_IRQS` — the GT-source bits (0–6) of the master register.
pub const GEN8_GT_IRQS: u32 = (1 << 7) - 1;

/// The master-register bit for a display pipe (`GEN8_DE_PIPE_IRQ`).
pub const fn gen8_de_pipe_irq(pipe: Pipe) -> u32 {
    1 << (16 + pipe as u32)
}

// ── DE summary registers ────────────────────────────────────────

/// `DEISR` (`display/intel_display_regs.h`).
pub const DEISR: u64 = 0x44000;
/// `DEIMR`.
pub const DEIMR: u64 = 0x44004;
/// `DEIIR`.
pub const DEIIR: u64 = 0x44008;
/// `DEIER`.
pub const DEIER: u64 = 0x4400c;
/// `GTISR` (GT summary).
pub const GTISR: u64 = 0x44010;
/// `GTIMR`.
pub const GTIMR: u64 = 0x44014;
/// `GTIIR`.
pub const GTIIR: u64 = 0x44018;
/// `GTIER`.
pub const GTIER: u64 = 0x4401c;

// ── GT banks ────────────────────────────────────────────────────

/// Number of GT IRQ banks (RCS/BCS, VCS0/VCS1, PM/GuC, VECS).
pub const GT_IRQ_BANKS: usize = 4;

/// `GEN8_GT_ISR(bank)` (`i915_reg.h`): 0x44300 + 0x10 per bank.
pub const fn gt_isr(bank: usize) -> u64 {
    0x44300 + 0x10 * bank as u64
}

/// `GEN8_GT_IMR(bank)`.
pub const fn gt_imr(bank: usize) -> u64 {
    gt_isr(bank) + 4
}

/// `GEN8_GT_IIR(bank)`.
pub const fn gt_iir(bank: usize) -> u64 {
    gt_isr(bank) + 8
}

/// `GEN8_GT_IER(bank)`.
pub const fn gt_ier(bank: usize) -> u64 {
    gt_isr(bank) + 0xc
}

/// Per-engine IRQ bits (`i915_reg.h`, `ENGINE_IRQ_SHIFT`):
/// render-user (bit 0), CS master error (bit 3), context
/// switch (bit 8), wait semaphore (bit 11).
pub const GT_RENDER_USER_IRQ: u32 = 1 << 0;
/// `GT_CS_MASTER_ERROR_IRQ`.
pub const GT_CS_MASTER_ERROR_IRQ: u32 = 1 << 3;
/// `GT_CONTEXT_SWITCH_IRQ`.
pub const GT_CONTEXT_SWITCH_IRQ: u32 = 1 << 8;
/// `GT_WAIT_SEMAPHORE_IRQ`.
pub const GT_WAIT_SEMAPHORE_IRQ: u32 = 1 << 11;

/// The per-engine IRQ set `gen8_gt_irq_postinstall` enables
/// (`gt/intel_gt_irq.c`).
pub const GT_ENGINE_IRQS: u32 =
    GT_RENDER_USER_IRQ | GT_CS_MASTER_ERROR_IRQ | GT_CONTEXT_SWITCH_IRQ | GT_WAIT_SEMAPHORE_IRQ;

/// Engine half shift within a bank (`RCS_IRQ_SHIFT` 0,
/// `BCS_IRQ_SHIFT` 16; same shape for VCS0/VCS1).
pub const fn gt_engine_shift(engine_half: usize) -> u32 {
    16 * engine_half as u32
}

// ── DE pipe registers ───────────────────────────────────────────

/// `GEN8_DE_PIPE_ISR(pipe)` (`display/intel_display_regs.h`):
/// 0x44400 + 0x10 per pipe.
pub const fn de_pipe_isr(pipe: Pipe) -> u64 {
    0x44400 + 0x10 * pipe as u64
}

/// `GEN8_DE_PIPE_IMR(pipe)`.
pub const fn de_pipe_imr(pipe: Pipe) -> u64 {
    de_pipe_isr(pipe) + 4
}

/// `GEN8_DE_PIPE_IIR(pipe)`.
pub const fn de_pipe_iir(pipe: Pipe) -> u64 {
    de_pipe_isr(pipe) + 8
}

/// `GEN8_DE_PIPE_IER(pipe)`.
pub const fn de_pipe_ier(pipe: Pipe) -> u64 {
    de_pipe_isr(pipe) + 0xc
}

/// `GEN8_PIPE_VBLANK` (bit 0).
pub const DE_PIPE_VBLANK: u32 = 1 << 0;
/// `GEN8_PIPE_VSYNC` (bit 1).
pub const DE_PIPE_VSYNC: u32 = 1 << 1;
/// `GEN8_PIPE_SCAN_LINE_EVENT` (bit 2).
pub const DE_PIPE_SCAN_LINE_EVENT: u32 = 1 << 2;
/// `GEN8_PIPE_PLANE_FLIP_DONE(n)` (bits 3–6, plane n 1–4).
pub const fn de_pipe_plane_flip_done(plane: u8) -> u32 {
    1 << (2 + plane as u32)
}
/// `GEN8_PIPE_PLANE_FAULT(n)` (bits 7–10, plane n 1–4).
pub const fn de_pipe_plane_fault(plane: u8) -> u32 {
    1 << (6 + plane as u32)
}
/// `GEN9_PIPE_CURSOR_FAULT` (bit 11, Gen9 only).
pub const DE_PIPE_CURSOR_FAULT: u32 = 1 << 11;
/// `GEN8_PIPE_CDCLK_CRC_DONE` (bit 28).
pub const DE_PIPE_CDCLK_CRC_DONE: u32 = 1 << 28;
/// `GEN8_PIPE_CDCLK_CRC_ERROR` (bit 29).
pub const DE_PIPE_CDCLK_CRC_ERROR: u32 = 1 << 29;
/// `GEN8_PIPE_FIFO_UNDERRUN` (bit 31).
pub const DE_PIPE_FIFO_UNDERRUN: u32 = 1 << 31;

// ── DE port registers ───────────────────────────────────────────

/// `GEN8_DE_PORT_ISR` (`display/intel_display_regs.h`).
pub const DE_PORT_ISR: u64 = 0x44440;
/// `GEN8_DE_PORT_IMR`.
pub const DE_PORT_IMR: u64 = 0x44444;
/// `GEN8_DE_PORT_IIR`.
pub const DE_PORT_IIR: u64 = 0x44448;
/// `GEN8_DE_PORT_IER`.
pub const DE_PORT_IER: u64 = 0x4444c;

/// `GEN8_AUX_CHANNEL_A` (bit 0).
pub const DE_PORT_AUX_A: u32 = 1 << 0;
/// `GEN8_DE_PORT_GMBUS` (bit 1).
pub const DE_PORT_GMBUS: u32 = 1 << 1;
/// `GEN9_AUX_CHANNEL_B` (bit 25).
pub const DE_PORT_AUX_B: u32 = 1 << 25;
/// `GEN9_AUX_CHANNEL_C` (bit 26).
pub const DE_PORT_AUX_C: u32 = 1 << 26;
/// `GEN9_AUX_CHANNEL_D` (bit 27).
pub const DE_PORT_AUX_D: u32 = 1 << 27;

/// The hotplug bit for a Gen9 DDI port (`GEN8_DE_PORT_HOTPLUG`):
/// bit (3 + pin − A). `None` for ports Gen9 does not have
/// (DDI F and above).
pub const fn de_port_hotplug_bit(port: Ddi) -> Option<u32> {
    match port {
        Ddi::A | Ddi::B | Ddi::C | Ddi::D | Ddi::E => Some(1 << (3 + port as u32)),
        _ => None,
    }
}

/// The Gen9 AUX-channel mask for the display-9 arm of
/// `gen8_de_port_aux_mask` (`display/intel_display_irq.c`):
/// AUX A + the Gen9 B/C/D channels.
pub const fn gen9_aux_mask() -> u32 {
    DE_PORT_AUX_A | DE_PORT_AUX_B | DE_PORT_AUX_C | DE_PORT_AUX_D
}

// ── DE misc / PCU registers ─────────────────────────────────────

/// `GEN8_DE_MISC_ISR`.
pub const DE_MISC_ISR: u64 = 0x44460;
/// `GEN8_DE_MISC_IMR`.
pub const DE_MISC_IMR: u64 = 0x44464;
/// `GEN8_DE_MISC_IIR`.
pub const DE_MISC_IIR: u64 = 0x44468;
/// `GEN8_DE_MISC_IER`.
pub const DE_MISC_IER: u64 = 0x4446c;
/// `GEN8_DE_EDP_PSR` (bit 19).
pub const DE_MISC_EDP_PSR: u32 = 1 << 19;
/// `GEN8_DE_MISC_GSE` (bit 27).
pub const DE_MISC_GSE: u32 = 1 << 27;

/// `EDP_PSR_IMR` (`display/intel_psr_regs.h`).
pub const EDP_PSR_IMR: u64 = 0x64834;
/// `EDP_PSR_IIR`.
pub const EDP_PSR_IIR: u64 = 0x64838;

/// `GEN8_DE_PCU_ISR`.
pub const DE_PCU_ISR: u64 = 0x444e0;
/// `GEN8_DE_PCU_IMR`.
pub const DE_PCU_IMR: u64 = 0x444e4;
/// `GEN8_DE_PCU_IIR`.
pub const DE_PCU_IIR: u64 = 0x444e8;
/// `GEN8_DE_PCU_IER`.
pub const DE_PCU_IER: u64 = 0x444ec;

// ── Reset / post-install primitives ─────────────────────────────

/// One IRQ register quartet's reset (`gen2_irq_reset`):
/// IMR = all-ones + posting read, IER = 0, IIR = all-ones
/// twice + posting reads. `isr` is unused by the sequence
/// (kept for the caller's address pinning).
pub fn reset_irq_regs(io: &impl MmioWindow, isr: u64, imr: u64, iir: u64, ier: u64) {
    let _ = isr;
    io.write32(imr, u32::MAX);
    let _ = io.read32(imr);
    io.write32(ier, 0);
    io.write32(iir, u32::MAX);
    let _ = io.read32(iir);
    io.write32(iir, u32::MAX);
    let _ = io.read32(iir);
}

/// One IRQ register quartet's install (`gen2_irq_init`):
/// returns `false` (and writes nothing) when the pending
/// register still holds bits — Linux warns on that path
/// instead of installing.
pub fn init_irq_regs(
    io: &impl MmioWindow,
    imr: u64,
    iir: u64,
    ier: u64,
    imr_val: u32,
    ier_val: u32,
) -> bool {
    if io.read32(iir) != 0 {
        return false;
    }
    io.write32(ier, ier_val);
    io.write32(imr, imr_val);
    true
}

/// `gen8_gt_irq_reset`: reset all four GT banks.
pub fn gen8_gt_irq_reset(io: &impl MmioWindow) {
    for bank in 0..GT_IRQ_BANKS {
        reset_irq_regs(io, gt_isr(bank), gt_imr(bank), gt_iir(bank), gt_ier(bank));
    }
}

/// `gen8_gt_irq_postinstall`: banks 0/1/3 enable the engine
/// IRQ set on both engine halves (bank 3: VECS only, low
/// half); bank 2 (PM/RPS + GuC) stays IER 0 / IMR all-ones —
/// its sources are enabled on demand. Returns `false` when
/// any bank still holds pending bits at install time.
pub fn gen8_gt_irq_postinstall(io: &impl MmioWindow) -> bool {
    let both = GT_ENGINE_IRQS | (GT_ENGINE_IRQS << 16);
    let mut ok = true;
    ok &= init_irq_regs(io, gt_imr(0), gt_iir(0), gt_ier(0), !both, both);
    ok &= init_irq_regs(io, gt_imr(1), gt_iir(1), gt_ier(1), !both, both);
    ok &= init_irq_regs(io, gt_imr(2), gt_iir(2), gt_ier(2), u32::MAX, 0);
    ok &= init_irq_regs(
        io,
        gt_imr(3),
        gt_iir(3),
        gt_ier(3),
        !GT_ENGINE_IRQS,
        GT_ENGINE_IRQS,
    );
    ok
}

/// `gen8_display_irq_reset`: EDP PSR IMR/IIR masked, the
/// three DE pipe quartets reset, DE port + DE misc + DE PCU
/// reset. The PCH split (SDE) reset lives in
/// `intel_gpu_dp.rs`, which owns the SDE registers.
pub fn gen8_display_irq_reset(io: &impl MmioWindow) {
    io.write32(EDP_PSR_IMR, u32::MAX);
    io.write32(EDP_PSR_IIR, u32::MAX);
    for pipe in [Pipe::A, Pipe::B, Pipe::C] {
        reset_irq_regs(
            io,
            de_pipe_isr(pipe),
            de_pipe_imr(pipe),
            de_pipe_iir(pipe),
            de_pipe_ier(pipe),
        );
    }
    reset_irq_regs(io, DE_PORT_ISR, DE_PORT_IMR, DE_PORT_IIR, DE_PORT_IER);
    reset_irq_regs(io, DE_MISC_ISR, DE_MISC_IMR, DE_MISC_IIR, DE_MISC_IER);
    reset_irq_regs(io, DE_PCU_ISR, DE_PCU_IMR, DE_PCU_IIR, DE_PCU_IER);
}

/// Master-IRQ disable (`gen8_master_intr_disable`, the
/// `gen8_irq_handler` entry): write 0 to the master register,
/// then sample the pending indications ("Now with master
/// disabled, get a sample of level indications for this
/// interrupt").
pub fn master_intr_disable(io: &(impl MmioWindow + ?Sized)) -> u32 {
    io.write32(GEN8_MASTER_IRQ, 0);
    io.read32(GEN8_MASTER_IRQ)
}

/// Master-IRQ enable (`gen8_irq_handler` exit): write the
/// CONTROL bit.
pub fn master_intr_enable(io: &(impl MmioWindow + ?Sized)) {
    io.write32(GEN8_MASTER_IRQ, GEN8_MASTER_IRQ_CONTROL);
}

// ── Decode ──────────────────────────────────────────────────────

/// The decoded `GEN8_MASTER_IRQ` pending mask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MasterIrq {
    /// RCS (bank 0 low half).
    pub gt_rcs: bool,
    /// BCS (bank 0 high half).
    pub gt_bcs: bool,
    /// VCS0 (bank 1 low half).
    pub gt_vcs0: bool,
    /// VCS1 (bank 1 high half).
    pub gt_vcs1: bool,
    /// PM/RPS (bank 2 low half).
    pub gt_pm: bool,
    /// GuC (bank 2 high half).
    pub gt_guc: bool,
    /// VECS (bank 3 low half).
    pub gt_vecs: bool,
    /// Display pipe A.
    pub pipe_a: bool,
    /// Display pipe B.
    pub pipe_b: bool,
    /// Display pipe C.
    pub pipe_c: bool,
    /// Display port (HPD / AUX / GMBUS).
    pub port: bool,
    /// Display misc (PSR / GSE).
    pub misc: bool,
    /// PCH (SDE).
    pub pch: bool,
    /// PCU.
    pub pcu: bool,
}

impl MasterIrq {
    /// Any GT source set (`master_ctl & GEN8_GT_IRQS`).
    pub const fn has_gt(self) -> bool {
        self.gt_rcs
            || self.gt_bcs
            || self.gt_vcs0
            || self.gt_vcs1
            || self.gt_pm
            || self.gt_guc
            || self.gt_vecs
    }

    /// Any display source set (`master_ctl & ~GEN8_GT_IRQS`).
    pub const fn has_display(self) -> bool {
        self.pipe_a || self.pipe_b || self.pipe_c || self.port || self.misc || self.pch || self.pcu
    }
}

/// Decode a `GEN8_MASTER_IRQ` read.
pub const fn decode_master(master_ctl: u32) -> MasterIrq {
    MasterIrq {
        gt_rcs: master_ctl & GEN8_GT_RCS_IRQ != 0,
        gt_bcs: master_ctl & GEN8_GT_BCS_IRQ != 0,
        gt_vcs0: master_ctl & GEN8_GT_VCS0_IRQ != 0,
        gt_vcs1: master_ctl & GEN8_GT_VCS1_IRQ != 0,
        gt_pm: master_ctl & GEN8_GT_PM_IRQ != 0,
        gt_guc: master_ctl & GEN8_GT_GUC_IRQ != 0,
        gt_vecs: master_ctl & GEN8_GT_VECS_IRQ != 0,
        pipe_a: master_ctl & GEN8_DE_PIPE_A_IRQ != 0,
        pipe_b: master_ctl & GEN8_DE_PIPE_B_IRQ != 0,
        pipe_c: master_ctl & GEN8_DE_PIPE_C_IRQ != 0,
        port: master_ctl & GEN8_DE_PORT_IRQ != 0,
        misc: master_ctl & GEN8_DE_MISC_IRQ != 0,
        pch: master_ctl & GEN8_DE_PCH_IRQ != 0,
        pcu: master_ctl & GEN8_PCU_IRQ != 0,
    }
}

/// Which GT banks `gen8_gt_irq_handler` services for a
/// decoded master mask (bank 0: RCS|BCS, bank 1: VCS0|VCS1,
/// bank 2: PM|GuC, bank 3: VECS).
pub const fn gt_banks_for_master(m: MasterIrq) -> [bool; GT_IRQ_BANKS] {
    [
        m.gt_rcs || m.gt_bcs,
        m.gt_vcs0 || m.gt_vcs1,
        m.gt_pm || m.gt_guc,
        m.gt_vecs,
    ]
}

/// Acknowledge one GT bank's pending interrupts (W1C):
/// read IIR, write the value back.
pub fn ack_gt_bank(io: &impl MmioWindow, bank: usize) -> u32 {
    let iir = io.read32(gt_iir(bank));
    io.write32(gt_iir(bank), iir);
    iir
}

/// The decoded `GEN8_DE_PORT_IIR` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortIrq {
    /// Hotplug per DDI port A–E.
    pub hotplug: [bool; 5],
    /// AUX-channel interrupt per DDI port A–D.
    pub aux: [bool; 4],
    /// GMBUS interrupt.
    pub gmbus: bool,
}

/// Decode a `GEN8_DE_PORT_IIR` read. The hotplug bits are
/// the HPD sources the session layer will thread; the AUX
/// bits are the display-9 arm of `gen8_de_port_aux_mask`.
pub const fn decode_port_iir(iir: u32) -> PortIrq {
    PortIrq {
        hotplug: [
            iir & (1 << 3) != 0,
            iir & (1 << 4) != 0,
            iir & (1 << 5) != 0,
            iir & (1 << 6) != 0,
            iir & (1 << 7) != 0,
        ],
        aux: [
            iir & DE_PORT_AUX_A != 0,
            iir & DE_PORT_AUX_B != 0,
            iir & DE_PORT_AUX_C != 0,
            iir & DE_PORT_AUX_D != 0,
        ],
        gmbus: iir & DE_PORT_GMBUS != 0,
    }
}

/// The decoded `GEN8_DE_PIPE_IIR` value (Gen9-relevant bits).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeIrq {
    /// VBLANK.
    pub vblank: bool,
    /// VSYNC.
    pub vsync: bool,
    /// Scan-line event.
    pub scan_line_event: bool,
    /// Plane flip-done per plane 1–4.
    pub flip_done: [bool; 4],
    /// Plane fault per plane 1–4.
    pub fault: [bool; 4],
    /// Cursor fault (Gen9 only).
    pub cursor_fault: bool,
    /// CDCLK CRC done.
    pub cdclk_crc_done: bool,
    /// CDCLK CRC error.
    pub cdclk_crc_error: bool,
    /// FIFO underrun.
    pub fifo_underrun: bool,
}

/// Decode a `GEN8_DE_PIPE_IIR` read.
pub const fn decode_pipe_iir(iir: u32) -> PipeIrq {
    PipeIrq {
        vblank: iir & DE_PIPE_VBLANK != 0,
        vsync: iir & DE_PIPE_VSYNC != 0,
        scan_line_event: iir & DE_PIPE_SCAN_LINE_EVENT != 0,
        flip_done: [
            iir & de_pipe_plane_flip_done(1) != 0,
            iir & de_pipe_plane_flip_done(2) != 0,
            iir & de_pipe_plane_flip_done(3) != 0,
            iir & de_pipe_plane_flip_done(4) != 0,
        ],
        fault: [
            iir & de_pipe_plane_fault(1) != 0,
            iir & de_pipe_plane_fault(2) != 0,
            iir & de_pipe_plane_fault(3) != 0,
            iir & de_pipe_plane_fault(4) != 0,
        ],
        cursor_fault: iir & DE_PIPE_CURSOR_FAULT != 0,
        cdclk_crc_done: iir & DE_PIPE_CDCLK_CRC_DONE != 0,
        cdclk_crc_error: iir & DE_PIPE_CDCLK_CRC_ERROR != 0,
        fifo_underrun: iir & DE_PIPE_FIFO_UNDERRUN != 0,
    }
}

// ── The Gen9 interrupt owner (`narf.intel.gen9_irq=1`) ──────────

/// The boot option that installs the Gen9 interrupt owner (default off:
/// without it no vector is allocated, no interrupt register is written and
/// hotplug stays polled at probe).
pub const OPT_IN: &str = "narf.intel.gen9_irq";

/// `narf.intel.gen9_irq=1`, with the strict grammar every Intel opt-in
/// uses ([`crate::intel_gpu_gt::boot_opt_in`]).
pub fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, OPT_IN)
}

/// `SDEIIR` (`display/intel_display_regs.h`), the SPT-class south display's
/// identity register (`gen8_read_and_ack_pch_irqs`).
pub const SDE_IIR: u64 = 0xc4008;
/// `SDE_HOTPLUG_MASK_SPT`: ports E (25), A (24), D (23), C (22), B (21).
pub const SDE_HOTPLUG_MASK_SPT: u32 = (1 << 25) | (1 << 24) | (1 << 23) | (1 << 22) | (1 << 21);
/// `SDE_GMBUS_CPT` (bit 17).
pub const SDE_GMBUS_CPT: u32 = 1 << 17;
/// `BXT_DE_PORT_HOTPLUG_MASK`: `GEN8_DE_PORT_HOTPLUG(HPD_PORT_A..C)`.
pub const BXT_DE_PORT_HOTPLUG_MASK: u32 = (1 << 3) | (1 << 4) | (1 << 5);
/// `BXT_DE_PORT_GMBUS` (bit 1, the bit [`DE_PORT_GMBUS`] names).
pub const BXT_DE_PORT_GMBUS: u32 = DE_PORT_GMBUS;

/// `gen8_de_pipe_fault_mask` for display 9: the plane 1-4 and cursor
/// faults.
pub const GEN9_DE_PIPE_FAULTS: u32 = de_pipe_plane_fault(1)
    | de_pipe_plane_fault(2)
    | de_pipe_plane_fault(3)
    | de_pipe_plane_fault(4)
    | DE_PIPE_CURSOR_FAULT;

/// `gen8_de_irq_postinstall`'s display-9 masks for one pipe: `(imr, ier)`.
/// The faults and `GEN8_PIPE_CDCLK_CRC_DONE` are unmasked; VBLANK, FIFO
/// underrun and the plane-1 flip done (`gen8_de_pipe_flip_done_mask`) are
/// enabled but stay masked until a consumer asks for them.
pub const fn gen9_de_pipe_init() -> (u32, u32) {
    let masked = GEN9_DE_PIPE_FAULTS | DE_PIPE_CDCLK_CRC_DONE;
    (
        !masked,
        masked | DE_PIPE_VBLANK | DE_PIPE_FIFO_UNDERRUN | de_pipe_plane_flip_done(1),
    )
}

/// `gen8_de_irq_postinstall`'s display-9 DE port masks: `(imr, ier)`. The
/// AUX channels (and on Gen9 LP GMBUS) are unmasked; Gen9 LP's hotplug
/// pins are enabled but masked until the hotplug setup unmasks them
/// (`bxt_hpd_irq_setup`).
pub const fn gen9_de_port_init(lp: bool) -> (u32, u32) {
    let masked = gen9_aux_mask() | if lp { BXT_DE_PORT_GMBUS } else { 0 };
    let enables = masked | if lp { BXT_DE_PORT_HOTPLUG_MASK } else { 0 };
    (!masked, enables)
}

/// `gen8_de_irq_postinstall`'s display-9 DE misc masks: `(imr, ier)`,
/// `GEN8_DE_EDP_PSR | GEN8_DE_MISC_GSE` unmasked and enabled.
pub const fn gen9_de_misc_init() -> (u32, u32) {
    let masked = DE_MISC_EDP_PSR | DE_MISC_GSE;
    (!masked, masked)
}

/// `gen8_gt_irq_postinstall`'s banks: `(imr, ier)` per bank. Bank 2 (PM/RPS
/// and GuC) stays disabled; its sources are enabled on demand.
pub const fn gen8_gt_init(bank: usize) -> (u32, u32) {
    let both = GT_ENGINE_IRQS | (GT_ENGINE_IRQS << 16);
    match bank {
        0 | 1 => (!both, both),
        3 => (!GT_ENGINE_IRQS, GT_ENGINE_IRQS),
        _ => (u32::MAX, 0),
    }
}

/// `irq_init` / `gen2_irq_init`: `assert_iir_is_zero` (a pending identity
/// is cleared twice and the install carries on, as Linux does after its
/// warning), then IER, then IMR with a posting read. Returns whether IIR
/// was clean.
fn irq_init(io: &(impl MmioWindow + ?Sized), regs: (u64, u64, u64), imr_val: u32, ier_val: u32) -> bool {
    let (imr, iir, ier) = regs;
    let clean = io.read32(iir) == 0;
    if !clean {
        io.write32(iir, u32::MAX);
        let _ = io.read32(iir);
        io.write32(iir, u32::MAX);
        let _ = io.read32(iir);
    }
    io.write32(ier, ier_val);
    io.write32(imr, imr_val);
    let _ = io.read32(imr);
    clean
}

/// `irq_reset` / `gen2_irq_reset` on one quartet (`reset_irq_regs`).
fn irq_reset(io: &(impl MmioWindow + ?Sized), regs: (u64, u64, u64)) {
    let (imr, iir, ier) = regs;
    io.write32(imr, u32::MAX);
    let _ = io.read32(imr);
    io.write32(ier, 0);
    io.write32(iir, u32::MAX);
    let _ = io.read32(iir);
    io.write32(iir, u32::MAX);
    let _ = io.read32(iir);
}

const fn gt_regs(bank: usize) -> (u64, u64, u64) {
    (gt_imr(bank), gt_iir(bank), gt_ier(bank))
}
const fn pipe_regs(pipe: Pipe) -> (u64, u64, u64) {
    (de_pipe_imr(pipe), de_pipe_iir(pipe), de_pipe_ier(pipe))
}
const PORT_REGS: (u64, u64, u64) = (DE_PORT_IMR, DE_PORT_IIR, DE_PORT_IER);
const MISC_REGS: (u64, u64, u64) = (DE_MISC_IMR, DE_MISC_IIR, DE_MISC_IER);
const PCU_REGS: (u64, u64, u64) = (DE_PCU_IMR, DE_PCU_IIR, DE_PCU_IER);
const PIPES: [Pipe; 3] = [Pipe::A, Pipe::B, Pipe::C];

/// `intel_display_power_is_enabled(POWER_DOMAIN_PIPE(pipe))` for display 9:
/// Pipe A is in PW_1 (always on with the display core); Pipes B and C are
/// PW_2 domains, read from `HSW_PWR_WELL_CTL2`'s PW_2 state.
pub fn pipe_powered(io: &(impl MmioWindow + ?Sized), pipe: Pipe) -> bool {
    use crate::intel_gpu_gen9_dc_states::{pw_state, HSW_PWR_WELL_CTL2, SKL_PW_CTL_IDX_PW_2};
    match pipe {
        Pipe::A => true,
        Pipe::B | Pipe::C => {
            let wells = io.read32(HSW_PWR_WELL_CTL2);
            wells != u32::MAX && wells & pw_state(SKL_PW_CTL_IDX_PW_2) != 0
        }
        _ => false,
    }
}

/// The hotplug half of a display interrupt, which the shared hotplug
/// monitor owns (`intel_gpu_dp`): it reads and acknowledges the bank's IIR
/// and latches the pins' long/short status itself, so a poll and an
/// interrupt never split one event.
pub trait Gen9Hotplug {
    /// Read and acknowledge `iir_reg` (`SDEIIR` or Gen9 LP's DE port IIR)
    /// and latch the owned pins it carries: the IIR read and whether a pin
    /// triggered; `None` on an all-ones read.
    fn ack(&self, io: &dyn MmioWindow, iir_reg: u64) -> Option<(u32, bool)>;
    /// Unmask (or mask again) the owned pins (`ibx_display_interrupt_update`
    /// / `bdw_update_port_irq`).
    fn unmask(&self, io: &dyn MmioWindow, unmask: bool) -> bool;
    /// Set the pins up again after a power loss (`intel_hpd_init`).
    fn reinit(&self, io: &dyn MmioWindow) -> bool;
}

/// The production [`Gen9Hotplug`]: the shared monitor.
#[derive(Clone, Copy, Debug, Default)]
pub struct MonitorHotplug;

impl Gen9Hotplug for MonitorHotplug {
    fn ack(&self, io: &dyn MmioWindow, iir_reg: u64) -> Option<(u32, bool)> {
        crate::intel_gpu_dp::hpd_irq_ack(io, iir_reg)
    }
    fn unmask(&self, io: &dyn MmioWindow, unmask: bool) -> bool {
        crate::intel_gpu_dp::hpd_irq_unmask(io, unmask)
    }
    fn reinit(&self, io: &dyn MmioWindow) -> bool {
        crate::intel_gpu_dp::hpd_irq_reinit(io)
    }
}

/// What one service pass found and acknowledged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gen9IrqEvents {
    /// Per GT bank, the IIR acknowledged (`gen8_gt_irq_handler`).
    pub gt: [u32; GT_IRQ_BANKS],
    /// A hotplug pin triggered (`intel_hpd_irq_handler`): the external-output
    /// pass runs.
    pub hotplug: bool,
    /// An AUX channel completed (`intel_dp_aux_irq_handler`).
    pub aux: bool,
    /// GMBUS (`intel_gmbus_irq_handler`).
    pub gmbus: bool,
    /// PSR (`intel_psr_irq_handler`) or GSE on DE misc.
    pub misc: u32,
    /// Per pipe A-C, the DE pipe IIR acknowledged (vblank, flip done,
    /// underrun, CRC, faults).
    pub pipes: [u32; 3],
    /// Master bits whose IIR read zero ("The master control interrupt
    /// lied").
    pub lied: u32,
}

impl Gen9IrqEvents {
    /// Any GT bank acknowledged.
    pub fn gt_any(&self) -> bool {
        self.gt.iter().any(|iir| *iir != 0)
    }
}

/// Why the owner refused or stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen9IrqError {
    /// A register read all-ones: the function is not in D0 or access was
    /// revoked.
    Unavailable,
    /// The master interrupt did not read enabled after the install.
    MasterOff,
}

/// The Gen9 interrupt owner's register half (`i915_irq.c`
/// `gen8_irq_reset` / `gen8_irq_postinstall` / `gen8_irq_handler`,
/// `intel_display_irq.c` `gen8_de_irq_handler`, `intel_hotplug_irq.c`
/// `spt_irq_handler` / `bxt_hpd_irq_handler`), free of delivery so fixtures
/// drive it directly. The hard handler only masks the master and records
/// it; the service pass, in task context, dispatches and re-enables it.
#[derive(Debug)]
pub struct Gen9IrqCore {
    /// Gen9 LP: hotplug and GMBUS are DE port sources; no PCH.
    lp: bool,
    /// `intel_irqs_enabled`: cleared by [`Self::suspend`].
    enabled: bool,
    /// The master sources the hard handler latched; the master stays off
    /// until the service pass acknowledges them.
    pending: u32,
    /// The owned hotplug pins are unmasked.
    hotplug_unmasked: bool,
}

impl Gen9IrqCore {
    pub const fn new(lp: bool) -> Self {
        Self {
            lp,
            enabled: false,
            pending: 0,
            hotplug_unmasked: false,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn hotplug_unmasked(&self) -> bool {
        self.hotplug_unmasked
    }

    /// `gen8_irq_reset`: the master off (`gen8_master_intr_disable`), the
    /// four GT banks, the display (`gen8_display_irq_reset`: EDP PSR masked,
    /// every powered pipe, DE port, DE misc) and the PCU. The SPT-class SDE
    /// block is the hotplug monitor's and is not reset here.
    pub fn reset(&mut self, io: &(impl MmioWindow + ?Sized)) {
        self.pending = 0;
        let _ = master_intr_disable(io);
        for bank in 0..GT_IRQ_BANKS {
            irq_reset(io, gt_regs(bank));
        }
        io.write32(EDP_PSR_IMR, u32::MAX);
        io.write32(EDP_PSR_IIR, u32::MAX);
        for pipe in PIPES {
            if pipe_powered(io, pipe) {
                irq_reset(io, pipe_regs(pipe));
            }
        }
        irq_reset(io, PORT_REGS);
        irq_reset(io, MISC_REGS);
        irq_reset(io, PCU_REGS);
    }

    /// `intel_irq_resume` / the install: enabled, [`Self::reset`], then
    /// `gen8_irq_postinstall` (the GT banks, `gen8_de_irq_postinstall` on
    /// every powered pipe, DE port and DE misc), the owned hotplug pins
    /// unmasked through the monitor, and the master enabled.
    pub fn install(
        &mut self,
        io: &dyn MmioWindow,
        hotplug: &dyn Gen9Hotplug,
    ) -> Result<(), Gen9IrqError> {
        if io.read32(GEN8_MASTER_IRQ) == u32::MAX {
            return Err(Gen9IrqError::Unavailable);
        }
        self.enabled = true;
        self.reset(io);
        for bank in 0..GT_IRQ_BANKS {
            let (imr, ier) = gen8_gt_init(bank);
            irq_init(io, gt_regs(bank), imr, ier);
        }
        let (imr, ier) = gen9_de_pipe_init();
        for pipe in PIPES {
            if pipe_powered(io, pipe) {
                irq_init(io, pipe_regs(pipe), imr, ier);
            }
        }
        let (imr, ier) = gen9_de_port_init(self.lp);
        irq_init(io, PORT_REGS, imr, ier);
        let (imr, ier) = gen9_de_misc_init();
        irq_init(io, MISC_REGS, imr, ier);
        self.hotplug_unmasked = hotplug.unmask(io, true);
        master_intr_enable(io);
        let master = io.read32(GEN8_MASTER_IRQ);
        if master == u32::MAX || master & GEN8_MASTER_IRQ_CONTROL == 0 {
            self.suspend(io, hotplug);
            return Err(Gen9IrqError::MasterOff);
        }
        Ok(())
    }

    /// `intel_irq_suspend`: `intel_irq_reset` and `irqs_enabled` cleared
    /// (the caller then synchronizes the vector). The owned hotplug pins are
    /// masked again, back to the monitor's polled posture.
    pub fn suspend(&mut self, io: &dyn MmioWindow, hotplug: &dyn Gen9Hotplug) {
        self.enabled = false;
        if core::mem::take(&mut self.hotplug_unmasked) {
            let _ = hotplug.unmask(io, false);
        }
        self.reset(io);
    }

    /// The hard handler (`gen8_irq_handler`'s entry): nothing while
    /// disabled; otherwise the master off and its sources sampled. With no
    /// source the master is enabled again (`IRQ_NONE`); otherwise the
    /// sources wait, master off, for [`Self::service`].
    pub fn hard_irq(&mut self, io: &(impl MmioWindow + ?Sized)) -> bool {
        if !self.enabled {
            return false;
        }
        if self.pending != 0 {
            // Already latched with the master off: no new edge can be ours.
            return true;
        }
        let master = master_intr_disable(io);
        if master == u32::MAX {
            return false;
        }
        let sources = master & !GEN8_MASTER_IRQ_CONTROL;
        if sources == 0 {
            master_intr_enable(io);
            return false;
        }
        self.pending = sources;
        true
    }

    /// One service pass in task context (the body of `gen8_irq_handler`):
    /// with nothing latched it masks the master and samples it itself (a
    /// lost MSI edge), then `gen8_gt_irq_handler` (each bank's IIR read and
    /// written back), `gen8_de_irq_handler` (DE misc, the DE port with Gen9
    /// LP's hotplug through the monitor, each pipe) and on display 9 proper
    /// the SPT-class PCH (`SDEIIR` through the monitor, `spt_irq_handler`),
    /// and the master enabled again. Nothing while disabled.
    ///
    /// `display` is asked for display access (the Gen9 `DC_off` reference)
    /// only when a display source is pending, and its guard is held through
    /// the display half; refused, the display sources stay latched with the
    /// master off for the next pass.
    pub fn service<G>(
        &mut self,
        io: &dyn MmioWindow,
        hotplug: &dyn Gen9Hotplug,
        display: impl FnOnce() -> Option<G>,
    ) -> Result<Gen9IrqEvents, Gen9IrqError> {
        let mut events = Gen9IrqEvents::default();
        if !self.enabled {
            return Ok(events);
        }
        let master = if self.pending != 0 {
            core::mem::take(&mut self.pending)
        } else {
            let sampled = master_intr_disable(io);
            if sampled == u32::MAX {
                return Err(Gen9IrqError::Unavailable);
            }
            sampled & !GEN8_MASTER_IRQ_CONTROL
        };
        let decoded = decode_master(master);
        for (bank, set) in gt_banks_for_master(decoded).into_iter().enumerate() {
            if !set {
                continue;
            }
            let iir = io.read32(gt_iir(bank));
            if iir == u32::MAX {
                return Err(Gen9IrqError::Unavailable);
            }
            if iir != 0 {
                io.write32(gt_iir(bank), iir);
                events.gt[bank] = iir;
            } else {
                events.lied |= master & GEN8_GT_IRQS;
            }
        }
        let _display = if decoded.has_display() {
            match display() {
                Some(guard) => Some(guard),
                None => {
                    self.pending = master & !GEN8_GT_IRQS;
                    return Ok(events);
                }
            }
        } else {
            None
        };
        if decoded.misc {
            let iir = io.read32(DE_MISC_IIR);
            if iir == u32::MAX {
                return Err(Gen9IrqError::Unavailable);
            }
            if iir != 0 {
                io.write32(DE_MISC_IIR, iir);
                events.misc = iir;
            } else {
                events.lied |= GEN8_DE_MISC_IRQ;
            }
        }
        if decoded.port {
            let iir = if self.lp {
                let (iir, triggered) = hotplug
                    .ack(io, DE_PORT_IIR)
                    .ok_or(Gen9IrqError::Unavailable)?;
                events.hotplug |= triggered;
                events.gmbus |= iir & BXT_DE_PORT_GMBUS != 0;
                iir
            } else {
                let iir = io.read32(DE_PORT_IIR);
                if iir == u32::MAX {
                    return Err(Gen9IrqError::Unavailable);
                }
                if iir != 0 {
                    io.write32(DE_PORT_IIR, iir);
                }
                iir
            };
            if iir == 0 {
                events.lied |= GEN8_DE_PORT_IRQ;
            }
            events.aux |= iir & gen9_aux_mask() != 0;
        }
        for (index, pipe) in PIPES.into_iter().enumerate() {
            if master & gen8_de_pipe_irq(pipe) == 0 {
                continue;
            }
            let iir = io.read32(de_pipe_iir(pipe));
            if iir == u32::MAX {
                return Err(Gen9IrqError::Unavailable);
            }
            if iir != 0 {
                io.write32(de_pipe_iir(pipe), iir);
                events.pipes[index] = iir;
            } else {
                events.lied |= gen8_de_pipe_irq(pipe);
            }
        }
        if decoded.pch && !self.lp {
            let (iir, triggered) = hotplug
                .ack(io, SDE_IIR)
                .ok_or(Gen9IrqError::Unavailable)?;
            if iir == 0 {
                events.lied |= GEN8_DE_PCH_IRQ;
            }
            events.hotplug |= triggered;
            events.gmbus |= iir & SDE_GMBUS_CPT != 0;
        }
        master_intr_enable(io);
        Ok(events)
    }
}

/// The owner's controller: the window and the core under one lock, which
/// the hard handler and the service pass share.
pub(crate) struct Controller<M> {
    inner: narf_lib::sync::IrqSafeSpinLock<(M, Gen9IrqCore)>,
}

impl<M: MmioWindow> Controller<M> {
    fn hard_irq(&self) -> narf_interrupts::dispatch::IrqStatus {
        let mut guard = self.inner.lock();
        let (io, core) = &mut *guard;
        if core.hard_irq(io) {
            narf_interrupts::dispatch::IrqStatus::Handled
        } else {
            narf_interrupts::dispatch::IrqStatus::None
        }
    }
}

fn handler<M: MmioWindow + Send + 'static>(cookie: u64) -> narf_interrupts::dispatch::IrqStatus {
    // SAFETY: the installed owner retains the controller for the vector's
    // whole life (it is never released while the handler is installed).
    unsafe { &*(cookie as *const Controller<M>) }.hard_irq()
}

type Window = crate::intel_gpu_gt_hw::AuthorizedWindow;

/// One installed owner: the controller, its MSI route and vector.
struct Installed {
    controller: alloc::sync::Arc<Controller<Window>>,
    route: narf_lib::sync::IrqSafeSpinLock<crate::intel_gpu_gt_irq::PciMsi>,
    vector: u8,
    bar: narf_bus::MmioRegion,
}

static OWNER: narf_lib::sync::IrqSafeSpinLock<Option<alloc::sync::Arc<Installed>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn owner() -> Option<alloc::sync::Arc<Installed>> {
    OWNER.lock().clone()
}

fn log(text: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "intel-gpu: {text}");
}

/// The Gen9 interrupt owner's vector for this BAR's function, if one is
/// installed: the execlists owner also wakes on it.
pub(crate) fn vector_for_bar(bar: &narf_bus::MmioRegion) -> Option<u8> {
    owner()
        .filter(|installed| installed.bar.phys == bar.phys)
        .map(|installed| installed.vector)
}

/// Whether the owner for this BAR has interrupts enabled
/// (`intel_irqs_enabled`); `false` without an owner.
pub(crate) fn irqs_enabled_for_bar(bar: &narf_bus::MmioRegion) -> bool {
    owner()
        .filter(|installed| installed.bar.phys == bar.phys)
        .is_some_and(|installed| installed.controller.inner.lock().1.enabled())
}

/// End of probe, with `narf.intel.gen9_irq=1` on a Gen9 display: allocate a
/// vector, install the hard handler, program and enable MSI, then
/// `gen8_irq_reset` + `gen8_irq_postinstall` with the owned hotplug pins
/// unmasked, register the system-sleep hooks and start the service task.
/// Without the option, off x86, or on any refusal, nothing stays installed.
/// Returns whether the owner runs.
pub(crate) fn install(
    opted_in: bool,
    platform: crate::intel_gpu_gt::Gen9Platform,
    bar: narf_bus::MmioRegion,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> bool {
    if !opted_in || !cfg!(target_arch = "x86_64") || OWNER.lock().is_some() {
        return false;
    }
    use crate::intel_gpu_gt_irq::MessageRoute as _;
    let Ok(mut route) = crate::intel_gpu_gt_irq::PciMsi::new(cap, device) else {
        log("Gen9 interrupts: MSI unavailable; hotplug stays polled");
        return false;
    };
    let Ok(vector) = narf_interrupts::vector::alloc() else {
        return false;
    };
    let window = Window::new(bar, cap);
    let controller = alloc::sync::Arc::new(Controller {
        inner: narf_lib::sync::IrqSafeSpinLock::new((window, Gen9IrqCore::new(platform.is_lp()))),
    });
    if route.program(vector).is_err() {
        if route.disable() {
            let _ = narf_interrupts::vector::free(vector);
        } else {
            core::mem::forget(route);
        }
        return false;
    }
    narf_interrupts::dispatch::install_handler_named(
        vector,
        "intel-gen9",
        alloc::sync::Arc::as_ptr(&controller) as u64,
        handler::<Window>,
    );
    let installed = alloc::sync::Arc::new(Installed {
        controller,
        route: narf_lib::sync::IrqSafeSpinLock::new(route),
        vector,
        bar,
    });
    if installed.route.lock().enable().is_err() || start(&installed).is_err() {
        // The handler, vector and route stay retained: a message the
        // device may still send must never reach another driver's vector.
        stop(&installed);
        log("Gen9 interrupts: install refused; hotplug stays polled");
        core::mem::forget(installed);
        return false;
    }
    *OWNER.lock() = Some(installed.clone());
    narf_power::system_pm::register_async_system_pm(PM_NAME, alloc::sync::Arc::new(SystemPm));
    let _ = narf_scheduler::spawn(service_task(installed));
    log("Gen9 interrupts installed: hotplug and display interrupts are delivered");
    true
}

/// The Gen9 `DC_off` reference the owner's display register accesses run
/// under (stricter than Linux, whose interrupt code takes no power domain);
/// `None` when DC states could not be exited.
fn display_access(bar: &narf_bus::MmioRegion) -> Option<crate::intel_gpu_gen9_dc_states::Gen9DcRef> {
    crate::intel_gpu_gen9_dc_states::acquire_for_bar(
        bar,
        crate::intel_gpu_gen9_dc_states::Gen9DcUser::Hpd,
    )
    .ok()
}

/// [`Gen9IrqCore::install`] on the owner's window, with DC states exited.
fn start(installed: &Installed) -> Result<(), Gen9IrqError> {
    let Some(_dc) = display_access(&installed.bar) else {
        return Err(Gen9IrqError::Unavailable);
    };
    let mut guard = installed.controller.inner.lock();
    let (io, core) = &mut *guard;
    core.install(&*io, &MonitorHotplug)
}

/// `intel_irq_suspend` on the owner: the core reset and disabled, MSI
/// delivery off, and the vector synchronized. The reset runs with DC states
/// exited when they can be; the software flag clears either way.
fn stop(installed: &Installed) {
    {
        let _dc = display_access(&installed.bar);
        let mut guard = installed.controller.inner.lock();
        let (io, core) = &mut *guard;
        core.suspend(&*io, &MonitorHotplug);
    }
    use crate::intel_gpu_gt_irq::MessageRoute as _;
    let _ = installed.route.lock().disable();
    narf_interrupts::dispatch::synchronize_irq(installed.vector);
}

/// The service task: each interrupt (or, for a lost edge, every 100 ms) one
/// [`Gen9IrqCore::service`] pass; a hotplug trigger runs the external-output
/// pass (`intel_hpd_irq_handler` → `i915_hotplug_work_func`) with no lock of
/// the owner held, under the display `DC_off` reference the pass takes.
async fn service_task(installed: alloc::sync::Arc<Installed>) {
    loop {
        // Snapshot the vector's count before the pass: an edge after it
        // still ends the wait.
        let wait = narf_interrupts::wait_for_irq_until(
            installed.vector,
            narf_time::Deadline::after_ms(100),
        );
        let result = {
            // Display interrupt registers are read with DC states exited
            // (stricter than Linux, whose handler takes no power domain);
            // the reference is taken only when a display source is pending,
            // so the idle watchdog never brings the display out of DC6.
            let mut guard = installed.controller.inner.lock();
            let (io, core) = &mut *guard;
            core.service(&*io, &MonitorHotplug, || display_access(&installed.bar))
        };
        match result {
            Ok(events) if events.hotplug => crate::intel_gpu::poll_dp_hpd_events(),
            Ok(_) => {}
            Err(_) => {
                log("Gen9 interrupts: registers unavailable; delivery stopped");
                stop(&installed);
            }
        }
        let _ = wait.await;
    }
}

const PM_NAME: &str = "intel-gen9-irq";

/// The system-sleep participant: `intel_irq_suspend` in the preparation
/// (before the late steps that need the master off, Gen9 LP DC9's
/// "Interrupts not disabled yet"), `intel_irq_resume` after the resume
/// (MSI programmed again, the reset, the postinstall with the hotplug pins
/// set up again, `intel_hpd_init`).
#[derive(Debug)]
struct SystemPm;

impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        alloc::boxed::Box::pin(async {
            if let Some(installed) = owner() {
                stop(&installed);
            }
            Ok(())
        })
    }
    fn resume_from_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        alloc::boxed::Box::pin(async {
            let Some(installed) = owner() else {
                return Ok(());
            };
            use crate::intel_gpu_gt_irq::MessageRoute as _;
            let routed = {
                let mut route = installed.route.lock();
                route.program(installed.vector).is_ok() && route.enable().is_ok()
            };
            let reinit = {
                let guard = installed.controller.inner.lock();
                let dyn_io: &dyn MmioWindow = &guard.0;
                MonitorHotplug.reinit(dyn_io)
            };
            if !reinit {
                log("Gen9 interrupts: hotplug not set up again after resume");
            }
            if !routed || start(&installed).is_err() {
                stop(&installed);
                log("Gen9 interrupts: not restored after resume; delivery stopped");
            }
            Ok(())
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Write-logging MMIO endpoint for the IRQ tests. Reads
    /// replay the last write to the offset (0 when never
    /// written), so reset/install sequences are observable
    /// and pending-bit fixtures can be staged by pre-writing.
    struct IrqMmio {
        regs: RefCell<Vec<(u64, u32)>>,
    }

    impl IrqMmio {
        fn new() -> Self {
            Self {
                regs: RefCell::new(Vec::new()),
            }
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.regs
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for IrqMmio {
        fn read32(&self, off: u64) -> u32 {
            self.regs
                .borrow()
                .iter()
                .rev()
                .find(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .unwrap_or(0)
        }

        fn write32(&self, off: u64, val: u32) {
            self.regs.borrow_mut().push((off, val));
        }
    }

    fn smoke_gen9_irq_register_addresses() -> TestResult {
        // Master + DE summary (Linux `intel_gmd_interrupt_regs.h`,
        // `display/intel_display_regs.h`).
        if GEN8_MASTER_IRQ != 0x44200
            || DEISR != 0x44000
            || DEIMR != 0x44004
            || DEIIR != 0x44008
            || DEIER != 0x4400c
            || GTISR != 0x44010
            || GTIMR != 0x44014
            || GTIIR != 0x44018
            || GTIER != 0x4401c
        {
            return TestResult::Fail("master/DE summary addresses wrong");
        }
        // GT banks: 0x44300 + 0x10 per bank.
        if gt_isr(0) != 0x44300
            || gt_isr(1) != 0x44310
            || gt_isr(2) != 0x44320
            || gt_isr(3) != 0x44330
            || gt_imr(2) != 0x44324
            || gt_iir(3) != 0x44338
            || gt_ier(1) != 0x4431c
        {
            return TestResult::Fail("GT bank addresses wrong");
        }
        // DE pipe: 0x44400 + 0x10 per pipe.
        if de_pipe_isr(Pipe::A) != 0x44400
            || de_pipe_isr(Pipe::B) != 0x44410
            || de_pipe_isr(Pipe::C) != 0x44420
            || de_pipe_imr(Pipe::B) != 0x44414
            || de_pipe_iir(Pipe::C) != 0x44428
            || de_pipe_ier(Pipe::A) != 0x4440c
        {
            return TestResult::Fail("DE pipe addresses wrong");
        }
        // DE port / misc / PCU + EDP PSR.
        if DE_PORT_ISR != 0x44440
            || DE_PORT_IMR != 0x44444
            || DE_PORT_IIR != 0x44448
            || DE_PORT_IER != 0x4444c
            || DE_MISC_ISR != 0x44460
            || DE_MISC_IIR != 0x44468
            || DE_PCU_ISR != 0x444e0
            || DE_PCU_IER != 0x444ec
            || EDP_PSR_IMR != 0x64834
            || EDP_PSR_IIR != 0x64838
        {
            return TestResult::Fail("DE port/misc/PCU addresses wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_register_addresses
    );

    fn smoke_gen9_irq_master_bits() -> TestResult {
        // `GEN8_MASTER_IRQ` bit layout (`intel_gmd_interrupt_regs.h`).
        if GEN8_MASTER_IRQ_CONTROL != 1 << 31
            || GEN8_PCU_IRQ != 1 << 30
            || GEN8_DE_PCH_IRQ != 1 << 23
            || GEN8_DE_MISC_IRQ != 1 << 22
            || GEN8_DE_PORT_IRQ != 1 << 20
            || GEN8_DE_PIPE_C_IRQ != 1 << 18
            || GEN8_DE_PIPE_B_IRQ != 1 << 17
            || GEN8_DE_PIPE_A_IRQ != 1 << 16
            || GEN8_GT_VECS_IRQ != 1 << 6
            || GEN8_GT_GUC_IRQ != 1 << 5
            || GEN8_GT_PM_IRQ != 1 << 4
            || GEN8_GT_VCS1_IRQ != 1 << 3
            || GEN8_GT_VCS0_IRQ != 1 << 2
            || GEN8_GT_BCS_IRQ != 1 << 1
            || GEN8_GT_RCS_IRQ != 1 << 0
            || GEN8_GT_IRQS != 0x7f
        {
            return TestResult::Fail("master IRQ bits wrong");
        }
        if gen8_de_pipe_irq(Pipe::A) != GEN8_DE_PIPE_A_IRQ
            || gen8_de_pipe_irq(Pipe::B) != GEN8_DE_PIPE_B_IRQ
            || gen8_de_pipe_irq(Pipe::C) != GEN8_DE_PIPE_C_IRQ
        {
            return TestResult::Fail("pipe IRQ helper wrong");
        }
        // The Gen11 HPD bit 21 (GEN11_DISPLAY_INT_CTL) does not
        // exist on Gen9: no constant claims it.
        if GEN8_GT_IRQS & (1 << 21) != 0 {
            return TestResult::Fail("Gen11-only bit leaked into Gen9 mask");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_irq", smoke_gen9_irq_master_bits);

    fn smoke_gen9_irq_gt_reset_sequence() -> TestResult {
        let io = IrqMmio::new();
        gen8_gt_irq_reset(&io);
        // Every bank: IMR all-ones, IER 0, IIR all-ones twice.
        for bank in 0..GT_IRQ_BANKS {
            if io.writes_to(gt_imr(bank)) != alloc::vec![u32::MAX] {
                return TestResult::Fail("GT reset IMR must be all-ones once");
            }
            if io.writes_to(gt_ier(bank)) != alloc::vec![0] {
                return TestResult::Fail("GT reset IER must be zero once");
            }
            if io.writes_to(gt_iir(bank)) != alloc::vec![u32::MAX, u32::MAX] {
                return TestResult::Fail("GT reset IIR must be all-ones twice");
            }
        }
        // No xe-era register is touched by the Gen9 reset.
        if io
            .regs
            .borrow()
            .iter()
            .any(|(o, _)| (0x190000..0x1a0000).contains(o))
        {
            return TestResult::Fail("Gen9 reset must not touch the xe IRQ block");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_gt_reset_sequence
    );

    fn smoke_gen9_irq_gt_postinstall_masks() -> TestResult {
        let io = IrqMmio::new();
        if !gen8_gt_irq_postinstall(&io) {
            return TestResult::Fail("postinstall must succeed with clear IIR");
        }
        let both = GT_ENGINE_IRQS | (GT_ENGINE_IRQS << 16);
        // Banks 0/1: both engine halves enabled, IMR complement.
        for bank in [0usize, 1] {
            if io.writes_to(gt_ier(bank)) != alloc::vec![both] {
                return TestResult::Fail("banks 0/1 IER must enable both halves");
            }
            if io.writes_to(gt_imr(bank)) != alloc::vec![!both] {
                return TestResult::Fail("banks 0/1 IMR must complement IER");
            }
        }
        // Bank 2 (PM/RPS + GuC): enabled on demand — IER 0.
        if io.writes_to(gt_ier(2)) != alloc::vec![0]
            || io.writes_to(gt_imr(2)) != alloc::vec![u32::MAX]
        {
            return TestResult::Fail("bank 2 must stay IER 0 / IMR all-ones");
        }
        // Bank 3 (VECS): low half only.
        if io.writes_to(gt_ier(3)) != alloc::vec![GT_ENGINE_IRQS]
            || io.writes_to(gt_imr(3)) != alloc::vec![!GT_ENGINE_IRQS]
        {
            return TestResult::Fail("bank 3 IER/IMR wrong");
        }
        // The engine set is exactly USER + CS_MASTER_ERROR +
        // CONTEXT_SWITCH + WAIT_SEMAPHORE.
        if GT_ENGINE_IRQS != (1 << 0) | (1 << 3) | (1 << 8) | (1 << 11) {
            return TestResult::Fail("engine IRQ set wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_gt_postinstall_masks
    );

    fn smoke_gen9_irq_postinstall_refuses_pending() -> TestResult {
        let io = IrqMmio::new();
        // Stage a pending bit in bank 1's IIR: the install
        // must refuse (Linux warns) and write nothing there.
        io.write32(gt_iir(1), GT_RENDER_USER_IRQ);
        if gen8_gt_irq_postinstall(&io) {
            return TestResult::Fail("postinstall must refuse a pending bank");
        }
        if !io.writes_to(gt_ier(1)).is_empty() || !io.writes_to(gt_imr(1)).is_empty() {
            return TestResult::Fail("refused bank must not be programmed");
        }
        // Bank 0 installed before the refusal was observed.
        if io.writes_to(gt_ier(0)).is_empty() {
            return TestResult::Fail("bank 0 must install before bank 1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_postinstall_refuses_pending
    );

    fn smoke_gen9_irq_display_reset_sequence() -> TestResult {
        let io = IrqMmio::new();
        gen8_display_irq_reset(&io);
        // EDP PSR masked first.
        if io.writes_to(EDP_PSR_IMR) != alloc::vec![u32::MAX]
            || io.writes_to(EDP_PSR_IIR) != alloc::vec![u32::MAX]
        {
            return TestResult::Fail("EDP PSR must be masked in display reset");
        }
        // Every pipe quartet reset in the gen2 shape.
        for pipe in [Pipe::A, Pipe::B, Pipe::C] {
            if io.writes_to(de_pipe_imr(pipe)) != alloc::vec![u32::MAX]
                || io.writes_to(de_pipe_ier(pipe)) != alloc::vec![0]
                || io.writes_to(de_pipe_iir(pipe)) != alloc::vec![u32::MAX, u32::MAX]
            {
                return TestResult::Fail("DE pipe reset sequence wrong");
            }
        }
        // Port + misc + PCU quartets reset.
        for (imr, iir, ier) in [
            (DE_PORT_IMR, DE_PORT_IIR, DE_PORT_IER),
            (DE_MISC_IMR, DE_MISC_IIR, DE_MISC_IER),
            (DE_PCU_IMR, DE_PCU_IIR, DE_PCU_IER),
        ] {
            if io.writes_to(imr) != alloc::vec![u32::MAX]
                || io.writes_to(ier) != alloc::vec![0]
                || io.writes_to(iir) != alloc::vec![u32::MAX, u32::MAX]
            {
                return TestResult::Fail("DE port/misc/PCU reset sequence wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_display_reset_sequence
    );

    fn smoke_gen9_irq_master_decode() -> TestResult {
        // GT-only: RCS + VECS.
        let gt = decode_master(GEN8_GT_RCS_IRQ | GEN8_GT_VECS_IRQ);
        if !gt.gt_rcs || !gt.gt_vecs || gt.has_display() || !gt.has_gt() {
            return TestResult::Fail("GT-only master decode wrong");
        }
        if gt_banks_for_master(gt) != [true, false, false, true] {
            return TestResult::Fail("GT-only bank map wrong");
        }
        // Display-only: pipe B + port + misc.
        let de = decode_master(GEN8_DE_PIPE_B_IRQ | GEN8_DE_PORT_IRQ | GEN8_DE_MISC_IRQ);
        if !de.pipe_b || !de.port || !de.misc || de.has_gt() || !de.has_display() {
            return TestResult::Fail("display-only master decode wrong");
        }
        if gt_banks_for_master(de) != [false, false, false, false] {
            return TestResult::Fail("display-only bank map must be empty");
        }
        // Mixed: PM + GuC → bank 2; VCS1 → bank 1; PCH + PCU.
        let mixed = decode_master(
            GEN8_GT_PM_IRQ | GEN8_GT_GUC_IRQ | GEN8_GT_VCS1_IRQ | GEN8_DE_PCH_IRQ | GEN8_PCU_IRQ,
        );
        if !mixed.gt_pm || !mixed.gt_guc || !mixed.gt_vcs1 || !mixed.pch || !mixed.pcu {
            return TestResult::Fail("mixed master decode wrong");
        }
        if gt_banks_for_master(mixed) != [false, true, true, false] {
            return TestResult::Fail("mixed bank map wrong");
        }
        // The CONTROL bit is not a source.
        if decode_master(GEN8_MASTER_IRQ_CONTROL).has_gt()
            || decode_master(GEN8_MASTER_IRQ_CONTROL).has_display()
        {
            return TestResult::Fail("CONTROL bit must decode to no source");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_master_decode
    );

    fn smoke_gen9_irq_port_decode() -> TestResult {
        // Hotplug bits: 3 + pin − A.
        if de_port_hotplug_bit(Ddi::A) != Some(1 << 3)
            || de_port_hotplug_bit(Ddi::B) != Some(1 << 4)
            || de_port_hotplug_bit(Ddi::C) != Some(1 << 5)
            || de_port_hotplug_bit(Ddi::D) != Some(1 << 6)
            || de_port_hotplug_bit(Ddi::E) != Some(1 << 7)
            || de_port_hotplug_bit(Ddi::F).is_some()
        {
            return TestResult::Fail("hotplug bits wrong");
        }
        // Gen9 AUX mask: A + B/C/D (no E/F AUX channel on Gen9).
        if gen9_aux_mask() != DE_PORT_AUX_A | DE_PORT_AUX_B | DE_PORT_AUX_C | DE_PORT_AUX_D
            || gen9_aux_mask() != (1 << 0) | (1 << 25) | (1 << 26) | (1 << 27)
        {
            return TestResult::Fail("Gen9 AUX mask wrong");
        }
        // Decode: HPD on B and E, AUX on C, GMBUS.
        let p = decode_port_iir((1 << 4) | (1 << 7) | DE_PORT_AUX_C | DE_PORT_GMBUS);
        if p.hotplug != [false, true, false, false, true]
            || p.aux != [false, false, true, false]
            || !p.gmbus
        {
            return TestResult::Fail("port IIR decode wrong");
        }
        // Quiet IIR decodes to nothing.
        if decode_port_iir(0) != PortIrq::default() {
            return TestResult::Fail("zero port IIR must decode empty");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_irq", smoke_gen9_irq_port_decode);

    fn smoke_gen9_irq_pipe_decode() -> TestResult {
        // Plane flip/fault bit positions: flip 3–6, fault 7–10.
        if de_pipe_plane_flip_done(1) != 1 << 3
            || de_pipe_plane_flip_done(4) != 1 << 6
            || de_pipe_plane_fault(1) != 1 << 7
            || de_pipe_plane_fault(4) != 1 << 10
        {
            return TestResult::Fail("plane flip/fault bits wrong");
        }
        let p = decode_pipe_iir(
            DE_PIPE_VBLANK
                | DE_PIPE_VSYNC
                | de_pipe_plane_flip_done(2)
                | de_pipe_plane_fault(4)
                | DE_PIPE_CURSOR_FAULT
                | DE_PIPE_CDCLK_CRC_ERROR
                | DE_PIPE_FIFO_UNDERRUN,
        );
        if !p.vblank
            || !p.vsync
            || p.scan_line_event
            || p.flip_done != [false, true, false, false]
            || p.fault != [false, false, false, true]
            || !p.cursor_fault
            || p.cdclk_crc_done
            || !p.cdclk_crc_error
            || !p.fifo_underrun
        {
            return TestResult::Fail("pipe IIR decode wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_irq", smoke_gen9_irq_pipe_decode);

    fn smoke_gen9_irq_master_gate_and_ack() -> TestResult {
        // Disable (`gen8_master_intr_disable`): write 0, then sample the
        // level indications, which the master's low bits carry.
        let hw = Gen9Hw::default();
        hw.set(gt_iir(0), GT_RENDER_USER_IRQ);
        hw.set(DE_PORT_IIR, DE_PORT_AUX_A);
        hw.write32(GEN8_MASTER_IRQ, GEN8_MASTER_IRQ_CONTROL);
        let pending = master_intr_disable(&hw);
        if pending != GEN8_GT_RCS_IRQ | GEN8_DE_PORT_IRQ {
            return TestResult::Fail("master disable must sample the pending mask");
        }
        if hw.writes_to(GEN8_MASTER_IRQ) != alloc::vec![GEN8_MASTER_IRQ_CONTROL, 0] {
            return TestResult::Fail("master disable must write 0 before sampling");
        }
        let io = IrqMmio::new();
        // Enable: write the CONTROL bit.
        master_intr_enable(&io);
        if io.writes_to(GEN8_MASTER_IRQ).last() != Some(&GEN8_MASTER_IRQ_CONTROL) {
            return TestResult::Fail("master enable must write CONTROL");
        }
        // Ack: read IIR, write it back (W1C).
        io.write32(gt_iir(0), GT_RENDER_USER_IRQ | GT_CONTEXT_SWITCH_IRQ);
        let acked = ack_gt_bank(&io, 0);
        if acked != GT_RENDER_USER_IRQ | GT_CONTEXT_SWITCH_IRQ {
            return TestResult::Fail("ack must return the IIR value");
        }
        if io.writes_to(gt_iir(0)).last() != Some(&(GT_RENDER_USER_IRQ | GT_CONTEXT_SWITCH_IRQ)) {
            return TestResult::Fail("ack must write the IIR value back");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_master_gate_and_ack
    );

    /// A Gen9 interrupt block shaped like the hardware: every IIR is
    /// write-1-to-clear, and `GEN8_MASTER_IRQ` reads its CONTROL bit as last
    /// written plus a level indication for each IIR holding a bit (GT banks
    /// by engine half, DE pipes A-C, port, misc, PCU and the PCH's
    /// `SDEIIR`). `dead` reads all-ones and drops writes.
    #[derive(Default)]
    pub(crate) struct Gen9Hw {
        regs: RefCell<alloc::collections::BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
        pub(crate) dead: core::cell::Cell<bool>,
    }

    impl Gen9Hw {
        /// Stage a register without logging a write.
        pub(crate) fn set(&self, off: u64, val: u32) {
            self.regs.borrow_mut().insert(off, val);
        }
        fn get(&self, off: u64) -> u32 {
            *self.regs.borrow().get(&off).unwrap_or(&0)
        }
        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
        fn log(&self) -> Vec<(u64, u32)> {
            self.writes.borrow().clone()
        }
        fn clear_log(&self) {
            self.writes.borrow_mut().clear();
        }
        fn iir(off: u64) -> bool {
            (0..GT_IRQ_BANKS).any(|b| off == gt_iir(b))
                || [Pipe::A, Pipe::B, Pipe::C]
                    .iter()
                    .any(|p| off == de_pipe_iir(*p))
                || [DE_PORT_IIR, DE_MISC_IIR, DE_PCU_IIR, SDE_IIR, EDP_PSR_IIR].contains(&off)
        }
        fn sources(&self) -> u32 {
            let half = |iir: u32, low: u32, high: u32| {
                (if iir & 0xffff != 0 { low } else { 0 }) | if iir >> 16 != 0 { high } else { 0 }
            };
            let mut m = half(self.get(gt_iir(0)), GEN8_GT_RCS_IRQ, GEN8_GT_BCS_IRQ)
                | half(self.get(gt_iir(1)), GEN8_GT_VCS0_IRQ, GEN8_GT_VCS1_IRQ)
                | half(self.get(gt_iir(2)), GEN8_GT_PM_IRQ, GEN8_GT_GUC_IRQ)
                | half(self.get(gt_iir(3)), GEN8_GT_VECS_IRQ, 0);
            for pipe in [Pipe::A, Pipe::B, Pipe::C] {
                if self.get(de_pipe_iir(pipe)) != 0 {
                    m |= gen8_de_pipe_irq(pipe);
                }
            }
            for (iir, bit) in [
                (DE_PORT_IIR, GEN8_DE_PORT_IRQ),
                (DE_MISC_IIR, GEN8_DE_MISC_IRQ),
                (DE_PCU_IIR, GEN8_PCU_IRQ),
                (SDE_IIR, GEN8_DE_PCH_IRQ),
            ] {
                if self.get(iir) != 0 {
                    m |= bit;
                }
            }
            m
        }
    }

    impl MmioWindow for Gen9Hw {
        fn read32(&self, off: u64) -> u32 {
            if self.dead.get() {
                return u32::MAX;
            }
            if off == GEN8_MASTER_IRQ {
                return (self.get(off) & GEN8_MASTER_IRQ_CONTROL) | self.sources();
            }
            self.get(off)
        }
        fn write32(&self, off: u64, val: u32) {
            if self.dead.get() {
                return;
            }
            self.writes.borrow_mut().push((off, val));
            if Self::iir(off) {
                let old = self.get(off);
                self.set(off, old & !val);
            } else {
                self.set(off, val);
            }
        }
    }

    /// The hotplug monitor's half, as a recorder: an `ack` reads and writes
    /// back the IIR and reports a trigger for the bank's hotplug bits.
    #[derive(Default)]
    struct Hotplug {
        acks: RefCell<Vec<(u64, u32)>>,
        unmasks: RefCell<Vec<bool>>,
    }

    impl Gen9Hotplug for Hotplug {
        fn ack(&self, io: &dyn MmioWindow, iir_reg: u64) -> Option<(u32, bool)> {
            let iir = io.read32(iir_reg);
            if iir == u32::MAX {
                return None;
            }
            if iir != 0 {
                io.write32(iir_reg, iir);
            }
            self.acks.borrow_mut().push((iir_reg, iir));
            let pins = if iir_reg == SDE_IIR {
                SDE_HOTPLUG_MASK_SPT
            } else {
                BXT_DE_PORT_HOTPLUG_MASK
            };
            Some((iir, iir & pins != 0))
        }
        fn unmask(&self, _io: &dyn MmioWindow, unmask: bool) -> bool {
            self.unmasks.borrow_mut().push(unmask);
            true
        }
        fn reinit(&self, _io: &dyn MmioWindow) -> bool {
            true
        }
    }

    /// `gen8_irq_reset` + `gen8_irq_postinstall` on display 9 proper with
    /// PW_2 off, values from Linux's masks: the master off first and on
    /// last; GT banks 0/1 IER 0x09090909 / IMR 0xF6F6F6F6
    /// (`GT_CS_MASTER_ERROR | GT_RENDER_USER | GT_CONTEXT_SWITCH |
    /// GT_WAIT_SEMAPHORE` on both halves), bank 2 off, bank 3 IER 0x909;
    /// pipe A IER 0x90000F89 / IMR 0xEFFFF07F (`gen8_de_pipe_fault_mask` and
    /// `CDCLK_CRC_DONE` unmasked; VBLANK, FIFO underrun and the plane-1 flip
    /// done enabled but masked) and pipes B/C untouched; DE port IER
    /// 0x0E000001 (`gen8_de_port_aux_mask`); DE misc 0x08080000 (EDP_PSR |
    /// GSE); no SDE write; the monitor asked to unmask its pins. Gen9 LP
    /// with PW_2 up programs pipes B/C too and its DE port IER is
    /// 0x0E00003B (+ GMBUS + `BXT_DE_PORT_HOTPLUG_MASK`, the pins masked).
    fn smoke_gen9_irq_owner_install_masks() -> TestResult {
        use crate::intel_gpu_gen9_dc_states::HSW_PWR_WELL_CTL2;
        let hw = Gen9Hw::default();
        let hotplug = Hotplug::default();
        let mut core = Gen9IrqCore::new(false);
        if core.install(&hw, &hotplug).is_err() || !core.enabled() {
            return TestResult::Fail("the install must enable");
        }
        let master = hw.writes_to(GEN8_MASTER_IRQ);
        if master.first() != Some(&0) || master.last() != Some(&GEN8_MASTER_IRQ_CONTROL) {
            return TestResult::Fail("the master is off first and on last");
        }
        let last_master = hw
            .log()
            .iter()
            .rposition(|(o, _)| *o == GEN8_MASTER_IRQ)
            .unwrap_or(0);
        if last_master + 1 != hw.log().len() {
            return TestResult::Fail("nothing may follow the master enable");
        }
        let last = |off: u64| hw.writes_to(off).last().copied();
        if last(gt_ier(0)) != Some(0x0909_0909)
            || last(gt_imr(0)) != Some(0xF6F6_F6F6)
            || last(gt_ier(1)) != Some(0x0909_0909)
            || last(gt_ier(2)) != Some(0)
            || last(gt_imr(2)) != Some(u32::MAX)
            || last(gt_ier(3)) != Some(0x909)
            || last(gt_imr(3)) != Some(0xFFFF_F6F6)
        {
            return TestResult::Fail("gen8_gt_irq_postinstall's banks");
        }
        if last(de_pipe_ier(Pipe::A)) != Some(0x9000_0F89)
            || last(de_pipe_imr(Pipe::A)) != Some(0xEFFF_F07F)
            || !hw.writes_to(de_pipe_ier(Pipe::B)).is_empty()
            || !hw.writes_to(de_pipe_imr(Pipe::C)).is_empty()
        {
            return TestResult::Fail("pipe A only, with PW_2 off");
        }
        if last(DE_PORT_IER) != Some(0x0E00_0001)
            || last(DE_PORT_IMR) != Some(0xF1FF_FFFE)
            || last(DE_MISC_IER) != Some(0x0808_0000)
            || last(DE_MISC_IMR) != Some(0xF7F7_FFFF)
            || last(EDP_PSR_IMR) != Some(u32::MAX)
            || last(DE_PCU_IER) != Some(0)
        {
            return TestResult::Fail("DE port, misc, PSR and PCU");
        }
        if hw.log().iter().any(|(o, _)| (0xc4000..0xc4010).contains(o))
            || *hotplug.unmasks.borrow() != [true]
            || !core.hotplug_unmasked()
        {
            return TestResult::Fail("the SDE block is the monitor's; it unmasks its own pins");
        }
        let hw = Gen9Hw::default();
        hw.set(HSW_PWR_WELL_CTL2, 0xC000_0000);
        let mut core = Gen9IrqCore::new(true);
        if core.install(&hw, &hotplug).is_err()
            || hw.writes_to(de_pipe_ier(Pipe::B)).last() != Some(&0x9000_0F89)
            || hw.writes_to(de_pipe_ier(Pipe::C)).last() != Some(&0x9000_0F89)
            || hw.writes_to(DE_PORT_IER).last() != Some(&0x0E00_003B)
            || hw.writes_to(DE_PORT_IMR).last() != Some(&0xF1FF_FFFC)
        {
            return TestResult::Fail("Gen9 LP with PW_2 up");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_owner_install_masks
    );

    /// `gen8_irq_handler`'s split: the hard handler only turns the master
    /// off and latches its sources (no IIR touched); the service pass
    /// acknowledges the GT bank, then DE misc, the DE port, each pipe and
    /// the PCH (through the hotplug monitor: `spt_irq_handler`'s trigger),
    /// and the master goes on last. A hard IRQ with no source re-enables the
    /// master and is not ours; a lost edge is drained by the service pass's
    /// own sample.
    fn smoke_gen9_irq_owner_dispatch() -> TestResult {
        let hw = Gen9Hw::default();
        let hotplug = Hotplug::default();
        let mut core = Gen9IrqCore::new(false);
        let _ = core.install(&hw, &hotplug);
        hw.set(gt_iir(0), GT_RENDER_USER_IRQ);
        hw.set(de_pipe_iir(Pipe::A), DE_PIPE_FIFO_UNDERRUN);
        hw.set(SDE_IIR, 1 << 21);
        hw.clear_log();
        if !core.hard_irq(&hw) || hw.log() != alloc::vec![(GEN8_MASTER_IRQ, 0)] {
            return TestResult::Fail("the hard handler only masks the master");
        }
        let Ok(events) = core.service(&hw, &hotplug, || Some(())) else {
            return TestResult::Fail("the service pass must run");
        };
        if events.gt != [GT_RENDER_USER_IRQ, 0, 0, 0]
            || events.pipes != [DE_PIPE_FIFO_UNDERRUN, 0, 0]
            || !events.hotplug
            || events.lied != 0
            || *hotplug.acks.borrow() != [(SDE_IIR, 1 << 21)]
        {
            return TestResult::Fail("GT, pipe A and the PCH hotplug decode");
        }
        let log = hw.log();
        let at = |w: (u64, u32)| log.iter().position(|x| *x == w);
        match (
            at((gt_iir(0), GT_RENDER_USER_IRQ)),
            at((de_pipe_iir(Pipe::A), DE_PIPE_FIFO_UNDERRUN)),
            at((SDE_IIR, 1 << 21)),
            log.last(),
        ) {
            (Some(g), Some(p), Some(h), Some(&(GEN8_MASTER_IRQ, GEN8_MASTER_IRQ_CONTROL)))
                if g < p && p < h => {}
            _ => return TestResult::Fail("GT, then the pipe, then the PCH, then the master"),
        }
        if hw.read32(GEN8_MASTER_IRQ) != GEN8_MASTER_IRQ_CONTROL {
            return TestResult::Fail("every source acknowledged, the master on");
        }
        hw.clear_log();
        if core.hard_irq(&hw)
            || hw.log() != alloc::vec![(GEN8_MASTER_IRQ, 0), (GEN8_MASTER_IRQ, GEN8_MASTER_IRQ_CONTROL)]
        {
            return TestResult::Fail("no source: the master on again, not handled");
        }
        hw.set(DE_MISC_IIR, DE_MISC_EDP_PSR);
        match core.service(&hw, &hotplug, || Some(())) {
            Ok(events) if events.misc == DE_MISC_EDP_PSR && !events.hotplug => {}
            _ => return TestResult::Fail("a lost edge is drained by the service pass"),
        }
        if hw.read32(GEN8_MASTER_IRQ) != GEN8_MASTER_IRQ_CONTROL {
            return TestResult::Fail("the drained pass re-enables the master");
        }
        // DC states not exited: the GT half runs, the display sources stay
        // latched with the master off, and the next pass takes them.
        hw.set(gt_iir(1), GT_RENDER_USER_IRQ);
        hw.set(de_pipe_iir(Pipe::A), DE_PIPE_VBLANK);
        let _ = core.hard_irq(&hw);
        let mut asked = false;
        match core.service(&hw, &hotplug, || {
            asked = true;
            None::<()>
        }) {
            Ok(events) if events.gt[1] == GT_RENDER_USER_IRQ && events.pipes == [0; 3] => {}
            _ => return TestResult::Fail("the GT half runs without display access"),
        }
        if !asked || hw.read32(GEN8_MASTER_IRQ) & GEN8_MASTER_IRQ_CONTROL != 0 {
            return TestResult::Fail("the display sources wait with the master off");
        }
        match core.service(&hw, &hotplug, || Some(())) {
            Ok(events) if events.pipes == [DE_PIPE_VBLANK, 0, 0] => {}
            _ => return TestResult::Fail("the next pass takes the latched display sources"),
        }
        let mut asked = false;
        let _ = core.service(&hw, &hotplug, || {
            asked = true;
            Some(())
        });
        if asked {
            return TestResult::Fail("an idle pass never asks for display access");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_owner_dispatch
    );

    /// Gen9 LP: hotplug and AUX share the DE port IIR, which the monitor
    /// acknowledges whole (`bxt_hpd_irq_handler`); the core writes the
    /// register only through it.
    fn smoke_gen9_irq_owner_lp_de_port_hotplug() -> TestResult {
        let hw = Gen9Hw::default();
        let hotplug = Hotplug::default();
        let mut core = Gen9IrqCore::new(true);
        let _ = core.install(&hw, &hotplug);
        hw.set(DE_PORT_IIR, (1 << 4) | DE_PORT_AUX_A);
        hw.clear_log();
        let _ = core.hard_irq(&hw);
        match core.service(&hw, &hotplug, || Some(())) {
            Ok(events) if events.hotplug && events.aux && !events.gmbus => {}
            _ => return TestResult::Fail("port B's hotplug beside AUX A"),
        }
        if *hotplug.acks.borrow() != [(DE_PORT_IIR, (1 << 4) | DE_PORT_AUX_A)]
            || hw.writes_to(DE_PORT_IIR) != alloc::vec![(1 << 4) | DE_PORT_AUX_A]
            || hw.read32(DE_PORT_IIR) != 0
        {
            return TestResult::Fail("one acknowledgement, through the monitor");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_owner_lp_de_port_hotplug
    );

    /// `intel_irq_suspend`: disabled, the owned pins masked again and
    /// `gen8_irq_reset` (the master off), after which the hard handler and
    /// the service pass touch nothing and the Gen9 display suspend owner's
    /// master check passes; `intel_irq_resume` installs again. A function
    /// that reads all-ones refuses the install and fails the service pass.
    fn smoke_gen9_irq_owner_suspend_and_resume() -> TestResult {
        let hw = Gen9Hw::default();
        let hotplug = Hotplug::default();
        let mut core = Gen9IrqCore::new(true);
        let _ = core.install(&hw, &hotplug);
        core.suspend(&hw, &hotplug);
        if core.enabled()
            || core.hotplug_unmasked()
            || *hotplug.unmasks.borrow() != [true, false]
            || hw.read32(GEN8_MASTER_IRQ) & GEN8_MASTER_IRQ_CONTROL != 0
        {
            return TestResult::Fail("suspend masks the pins and turns the master off");
        }
        hw.set(gt_iir(0), GT_RENDER_USER_IRQ);
        hw.clear_log();
        if core.hard_irq(&hw)
            || core.service(&hw, &hotplug, || Some(())) != Ok(Gen9IrqEvents::default())
            || !hw.log().is_empty()
        {
            return TestResult::Fail("a suspended owner touches nothing");
        }
        if crate::intel_gpu_gen9_suspend::quiesce_interrupts(&hw).is_err() {
            return TestResult::Fail("the display suspend owner sees the master off");
        }
        if core.install(&hw, &hotplug).is_err()
            || !core.enabled()
            || hw.read32(GEN8_MASTER_IRQ) & GEN8_MASTER_IRQ_CONTROL == 0
            || hw.read32(gt_iir(0)) != 0
        {
            return TestResult::Fail("the resume installs again on a clean block");
        }
        hw.dead.set(true);
        if core.service(&hw, &hotplug, || Some(())) != Err(Gen9IrqError::Unavailable) {
            return TestResult::Fail("lost access fails the service pass");
        }
        let mut fresh = Gen9IrqCore::new(false);
        if fresh.install(&hw, &hotplug) != Err(Gen9IrqError::Unavailable) || fresh.enabled() {
            return TestResult::Fail("an all-ones master refuses the install");
        }
        if OPT_IN != "narf.intel.gen9_irq"
            || !requested(narf_boot::args::KernelCmdline::new("narf.intel.gen9_irq=1"))
            || requested(narf_boot::args::KernelCmdline::new("narf.intel.gen9_irq=yes"))
        {
            return TestResult::Fail("strict opt-in grammar");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_irq",
        smoke_gen9_irq_owner_suspend_and_resume
    );
}
