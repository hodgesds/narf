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
//! # What this module is not
//!
//! Register-level routing only: reset / post-install / decode /
//! ack primitives plus fixtures. No live IRQ-handler wiring —
//! there is no interrupt-domain registration in this crate yet,
//! and the HPD decode (`decode_port_iir`) is the input the
//!   future session threading consumes, not the threading
//!   itself. Live dispatch is a named remainder (spec §12.7).

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

/// Master-IRQ disable (`gen8_irq_handler` entry): read the
/// pending mask, then write 0 to the master register.
pub fn master_intr_disable(io: &impl MmioWindow) -> u32 {
    let pending = io.read32(GEN8_MASTER_IRQ);
    io.write32(GEN8_MASTER_IRQ, 0);
    pending
}

/// Master-IRQ enable (`gen8_irq_handler` exit): write the
/// CONTROL bit.
pub fn master_intr_enable(io: &impl MmioWindow) {
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
        let io = IrqMmio::new();
        // Disable: write 0, read back the pending mask.
        io.write32(GEN8_MASTER_IRQ, GEN8_GT_RCS_IRQ | GEN8_DE_PORT_IRQ);
        let pending = master_intr_disable(&io);
        if pending != GEN8_GT_RCS_IRQ | GEN8_DE_PORT_IRQ {
            return TestResult::Fail("master disable must read back the pending mask");
        }
        if io.writes_to(GEN8_MASTER_IRQ).last() != Some(&0) {
            return TestResult::Fail("master disable must write 0");
        }
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
}
