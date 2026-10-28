//! RCS0 command submission — execlists path for Gen12 (TGL / ADL / RPL).
//!
//! Spec: `drivers/gpu/specification/intel_gpu.md` §7.
//!
//! Until this module the Intel driver could identify, probe and
//! modeset, but nothing could be *submitted* to the render engine:
//! no rings, no contexts, no execbuffer path existed. This module
//! is the first submission machinery — the Gen12 execlists
//! protocol end to end:
//!
//! - **Contexts.** Each context owns a GGTT-backed logical ring
//!   context (LRC) image whose register-state page is built from
//!   the PRM template (Gen12 engine-relative `MI_LOAD_REGISTER_IMM` groups),
//!   a 128 KiB ring buffer, and a per-context hardware status
//!   page (HWSP) carrying the breadcrumb sequence number.
//! - **Submission.** `submit` appends `MI_BATCH_BUFFER_START`
//!   (GGTT) + a `MI_STORE_DWORD_IMM` breadcrumb to the context's
//!   ring, advances the image tail, and — when an execlist port
//!   is free — writes the context descriptors to the ELSP in the
//!   hardware order (port 1 high/low, then port 0 high/low; the
//!   final write is the doorbell).
//! - **Completion.** The engine status page (programmed into
//!   `RING_HWS_PGA` at engine init) receives Gen12-format context
//!   status buffer (CSB) entries; `poll_completions` drains them
//!   (promote / preempt / complete), retires requests, frees
//!   batch allocations and pumps the next ports.
//!
//! ## Addressing scope
//!
//! Contexts address through the **GGTT by default**: the
//! descriptor mode is Legacy-64B, the PDP fields of the
//! register-state image are written zero, and batches are
//! submitted with the GGTT address-space indicator. A context
//! can additionally carry a PPGTT root from the walker in
//! [`crate::intel_gpu_ppgtt`] (#1012): [`RcsEngine::attach_ppgtt`]
//! programs the root into the image's PDP0 pair (the 4-level
//! root slot) so the hardware walk runs under the context.
//! Batch *allocations* stay GGTT-backed even then. VA-batch
//! submission ([`RcsEngine::submit_ppgtt`], the PPGTT form of
//! the batch-start) landed with the media engines in
//! [`crate::intel_gpu_media`] (#1022), which also generalises
//! this engine over the execlists engine identity
//! ([`EngineSpec`]). The
//! GGTT machinery of [`crate::intel_gpu_gtt`] is used as-is;
//! this module adds the missing GGTT *allocator* (a first-fit
//! arena above the scanout reservation) to own ring / image /
//! batch placements.
//!
//! ## References
//!
//! - Tiger Lake PRM Vol. 2a / 2c — MI command encodings and the
//!   execlists / logical-ring-context model; Vol. 5 — GTT.
//! - MIT i915 `gt/intel_lrc.c` Gen12 RCS/XCS register tables —
//!   the generation-specific restore layout and relative-MMIO selector.
//! - `intel_lrc.c` / `intel_engine` headers of the public i915
//!   driver (MIT-licensed) — cross-check for the Gen11+ context
//!   descriptor upper-dword format, the Gen12 CSB entry format,
//!   and the HWSP CSB offsets (`I915_HWS_CSB_BUF0_INDEX`,
//!   `CNL_HWS_CSB_WRITE_INDEX`).
//!
//! The CSB depth is twelve (MIT intel_lrc_reg.h). The 48-page image
//! allocation bounds the 14-page Gen12 render image. These model-checked
//! encodings do not establish full GT setup, safe userspace execution,
//! render-cache completion or reset/loss handling; the userspace gate in
//! intel_gpu_render remains closed until those owners exist.

use core::sync::atomic::{compiler_fence, Ordering};

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_forcewake::{Forcewake, FwDomain};
use crate::intel_gpu_gtt::{
    encode_scanout_pte, encode_table_entry, ggtt_va_size, PatSlot, GGTT_ARRAY_BASE, GTT_PAGE_SIZE,
};

// ── RCS0 engine register map (TGL PRM Vol. 2c; engine base 0x2000) ──

/// RCS0 engine MMIO base within BAR0.
pub const RCS_BASE: u64 = 0x2000;
/// `RING_HWS_PGA` — GGTT address of the engine hardware status page.
pub const RING_HWS_PGA: u64 = RCS_BASE + 0x80;
/// `RING_TAIL` (execlists mode: shadowed by the context image).
pub const RING_TAIL: u64 = RCS_BASE + 0x30;
/// `RING_HEAD`.
pub const RING_HEAD: u64 = RCS_BASE + 0x34;
/// `RING_START` — GGTT address of the ring buffer.
pub const RING_START: u64 = RCS_BASE + 0x38;
/// `RING_CTL`.
pub const RING_CTL: u64 = RCS_BASE + 0x3C;
/// `RING_MI_MODE`.
pub const RING_MI_MODE: u64 = RCS_BASE + 0x9C;
/// `R_PWR_CLK_STATE` — SSEU power/clock state saved per context.
pub const R_PWR_CLK_STATE: u64 = 0x20C8;
/// `RING_BBADDR` / batch-buffer current head (low / upper).
pub const RING_BBADDR: u64 = RCS_BASE + 0x140;
/// `RING_BBADDR_UDW`.
pub const RING_BBADDR_UDW: u64 = RCS_BASE + 0x168;
/// `RING_BBSTATE`.
pub const RING_BBSTATE: u64 = RCS_BASE + 0x110;
/// `RING_SBBADDR` / second-level batch head (low / upper / state).
pub const RING_SBBADDR: u64 = RCS_BASE + 0x114;
/// `RING_SBBADDR_UDW`.
pub const RING_SBBADDR_UDW: u64 = RCS_BASE + 0x11C;
/// `RING_SBBSTATE`.
pub const RING_SBBSTATE: u64 = RCS_BASE + 0x118;
/// `RING_BB_PER_CTX_PTR` — per-context workaround batch pointer.
pub const RING_BB_PER_CTX_PTR: u64 = RCS_BASE + 0x1C0;
/// `RING_INDIRECT_CTX` / its offset register (RCS-only pair).
pub const RING_INDIRECT_CTX: u64 = RCS_BASE + 0x1C4;
/// `RING_INDIRECT_CTX_OFFSET`.
pub const RING_INDIRECT_CTX_OFFSET: u64 = RCS_BASE + 0x1C8;
/// `RING_ELSP` — execlist submission port (write-only doorbell).
pub const RING_ELSP: u64 = RCS_BASE + 0x230;
/// `RING_EXECLIST_STATUS` — posting-read target after an ELSP write.
pub const RING_EXECLIST_STATUS: u64 = RCS_BASE + 0x234;
/// `RING_CONTEXT_CONTROL`.
pub const RING_CONTEXT_CONTROL: u64 = RCS_BASE + 0x244;
/// `RING_CTX_TIMESTAMP`.
pub const RING_CTX_TIMESTAMP: u64 = RCS_BASE + 0x3A8;
/// `GEN8_RING_PDP_LDW(n)` for the engine at `base`.
pub const fn ring_pdp_ldw_at(base: u64, n: u32) -> u64 {
    base + 0x270 + 8 * (n as u64)
}
/// `GEN8_RING_PDP_UDW(n)` for the engine at `base`.
pub const fn ring_pdp_udw_at(base: u64, n: u32) -> u64 {
    ring_pdp_ldw_at(base, n) + 4
}
/// `GEN8_RING_PDP_LDW(n)` — PPGTT descriptor pointer low dwords.
pub const fn ring_pdp_ldw(n: u32) -> u64 {
    ring_pdp_ldw_at(RCS_BASE, n)
}
/// `GEN8_RING_PDP_UDW(n)`.
pub const fn ring_pdp_udw(n: u32) -> u64 {
    ring_pdp_ldw(n) + 4
}

/// `RING_HWS_PGA` offset from an engine register-block base.
pub const RING_HWS_PGA_OFF: u64 = 0x80;
/// `RING_ELSP` offset from an engine register-block base.
pub const RING_ELSP_OFF: u64 = 0x230;
/// `RING_EXECLIST_STATUS` offset from an engine register-block
/// base.
pub const RING_EXECLIST_STATUS_OFF: u64 = 0x234;

// ── Engine identity (Gen11+ descriptor fields) ──────────────────
//
// The execlists machinery in this module is not render-specific:
// every Gen11+ engine (RCS, BCS, VCS, VECS) shares the ring /
// context-image / CSB protocol and differs only in its register
// base, its descriptor engine class + instance, its context
// image size, and the render-only `R_PWR_CLK_STATE` template
// group. `EngineSpec` carries exactly those differences; the
// media engines in `intel_gpu_media` instantiate the same
// `RcsEngine` over their own specs.

/// Descriptor engine-class field (bits 61:63) values, Gen11+.
///
/// The numbering is the one the Gen12-era execlists driver
/// writes into the descriptor: i915's `intel_engine_types.h`
/// class defines of the v5.10 tree (`RENDER_CLASS` 0,
/// `VIDEO_DECODE_CLASS` 1, `VIDEO_ENHANCEMENT_CLASS` 2,
/// `COPY_ENGINE_CLASS` 3, `OTHER_CLASS` 4), ORed into the
/// descriptor upper dword at `GEN11_ENGINE_CLASS_SHIFT` (61)
/// by `intel_lrc.c`. (Later i915 trees renumbered their
/// internal class enum; the Gen12 execlists descriptor is
/// written by the Gen12-era construction, which is what this
/// follows.)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EngineClass {
    /// Render command streamer (RCS).
    Render,
    /// Video command streamer (VCS / BSD).
    VideoDecode,
    /// Video enhancement command streamer (VECS / VEBox).
    VideoEnhance,
    /// Blitter / copy engine (BCS).
    Copy,
    /// Anything else.
    Other,
}

impl EngineClass {
    /// The value this class occupies in descriptor bits 61:63.
    pub const fn descriptor_value(self) -> u64 {
        match self {
            EngineClass::Render => 0,
            EngineClass::VideoDecode => 1,
            EngineClass::VideoEnhance => 2,
            EngineClass::Copy => 3,
            EngineClass::Other => 4,
        }
    }
}

/// One execlists engine's identity: everything about the shared
/// machinery that varies per engine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EngineSpec {
    /// Short name ("rcs0", "vcs0", ...) for logs and reporting.
    pub name: &'static str,
    /// Descriptor engine class.
    pub class: EngineClass,
    /// Descriptor engine instance (descriptor bits 48:53).
    pub instance: u8,
    /// Engine register block base within BAR0.
    pub base: u64,
    /// Pages allocated per context image (an allocation bound
    /// above the engine's hardware image; see the owning
    /// module's notes).
    pub image_pages: u32,
}

impl EngineSpec {
    /// Absolute `RING_HWS_PGA` for this engine.
    pub const fn hws_pga(&self) -> u64 {
        self.base + RING_HWS_PGA_OFF
    }
    /// Absolute `RING_ELSP` for this engine.
    pub const fn elsp(&self) -> u64 {
        self.base + RING_ELSP_OFF
    }
    /// Absolute `RING_EXECLIST_STATUS` for this engine.
    pub const fn execlist_status(&self) -> u64 {
        self.base + RING_EXECLIST_STATUS_OFF
    }
    /// Whether the register-state template carries the
    /// render-only `R_PWR_CLK_STATE` group (i915 programs
    /// `CTX_R_PWR_CLK_STATE` only for render-class contexts;
    /// its Gen12 XCS template has no third group).
    pub const fn has_pwr_clk_state(&self) -> bool {
        matches!(self.class, EngineClass::Render)
    }
}

/// RCS0: render class, instance 0, register base 0x2000.
pub const RCS0_SPEC: EngineSpec = EngineSpec {
    name: "rcs0",
    class: EngineClass::Render,
    instance: 0,
    base: RCS_BASE,
    image_pages: RCS_IMAGE_PAGES,
};

// ── MI command codecs (TGL PRM Vol. 2a) ─────────────────────────

/// `MI_NOOP` — also the ring wrap-padding dword.
pub const MI_NOOP: u32 = 0x0000_0000;
/// `MI_BATCH_BUFFER_END`.
pub const MI_BATCH_BUFFER_END: u32 = 0x0A << 23;
/// Address-space indicator bit of `MI_BATCH_BUFFER_START`:
/// clear = GGTT, set = PPGTT.
pub const BB_START_ASI_PPGTT: u32 = 1 << 8;
/// Second-level batch bit of `MI_BATCH_BUFFER_START`. Never set
/// by this driver (all batches are first-level); defined so the
/// decoder in the fixtures can reject it explicitly.
pub const BB_START_SECOND_LEVEL: u32 = 1 << 22;
/// `MI_USE_GGTT` for `MI_STORE_DWORD_IMM` — the store address is
/// a GGTT offset, not a raw physical address.
pub const MI_USE_GGTT: u32 = 1 << 22;

/// Encode a first-level `MI_BATCH_BUFFER_START` against the
/// GGTT (3 dwords: header, address low, address high).
pub fn mi_batch_buffer_start_ggtt(ggtt_addr: u64) -> [u32; 3] {
    [
        (0x31 << 23) | 1,
        (ggtt_addr & 0xFFFF_FFFF) as u32,
        (ggtt_addr >> 32) as u32,
    ]
}

/// Encode a first-level `MI_BATCH_BUFFER_START` against the
/// context's PPGTT: identical framing to the GGTT form with
/// the address-space indicator set, and the address is a
/// virtual address in the attached PPGTT (see
/// [`RcsEngine::attach_ppgtt`] and [`RcsEngine::submit_ppgtt`]).
pub fn mi_batch_buffer_start_ppgtt(ppgtt_va: u64) -> [u32; 3] {
    [
        (0x31 << 23) | 1 | BB_START_ASI_PPGTT,
        (ppgtt_va & 0xFFFF_FFFF) as u32,
        (ppgtt_va >> 32) as u32,
    ]
}

/// Encode a `MI_STORE_DWORD_IMM` (Gen4+ 64-bit-address form)
/// writing `data` to the GGTT address `ggtt_addr` (4 dwords).
pub fn mi_store_dword_imm_ggtt(ggtt_addr: u64, data: u32) -> [u32; 4] {
    [
        (0x20 << 23) | 2 | MI_USE_GGTT,
        (ggtt_addr & 0xFFFF_FFFF) as u32,
        (ggtt_addr >> 32) as u32,
        data,
    ]
}

/// Encode an `MI_LOAD_REGISTER_IMM` header for `n` register
/// pairs. `force_posted` sets the posted-write bit the PRM
/// requires for context-restore batches.
pub fn mi_load_register_imm(n: u32, force_posted: bool) -> u32 {
    let mut v = (0x22 << 23) | (2 * n - 1);
    if force_posted {
        v |= 1 << 12;
    }
    v
}

// ── Context descriptor (Gen11+ format) ──────────────────────────

/// Descriptor bit 0 — the context is valid.
pub const DESC_VALID: u64 = 1 << 0;
/// Descriptor mode field (bits 4:3) — Legacy 64-bit context:
/// 64-bit batch/ring pointers, GGTT addressing for the context.
pub const DESC_MODE_LEGACY_64B: u64 = 3 << 3;
/// Descriptor bit 5 — L3 / LLC coherent context.
pub const DESC_L3LLC_COHERENT: u64 = 1 << 5;
/// Descriptor bit 8 — privileged context (required for
/// `MI_STORE_DWORD_IMM` from the ring on Gen12).
pub const DESC_PRIVILEGE: u64 = 1 << 8;
/// SW context ID the hardware reports for "no context" in the
/// CSB. Never assigned to a real context.
pub const IDLE_SW_ID: u16 = 0x7FF;

/// Build the 64-bit execlists context descriptor for a context
/// image at GGTT offset `lrca` (must be 4 KiB aligned and below
/// 4 GiB — the LRCA field is descriptor bits 31:12) with software
/// context id `sw_ctx_id` (11 bits, encoded in the Gen11+ upper
/// dword at bits 37:47), for the engine `spec` names. The
/// descriptor's engine class (bits 61:63) and engine instance
/// (bits 48:53) come from the spec; the SW counter stays 0 —
/// this driver matches CSB events by SW id + FIFO order.
pub fn context_descriptor_for(spec: &EngineSpec, lrca: u32, sw_ctx_id: u16) -> u64 {
    debug_assert!(lrca & 0xFFF == 0);
    debug_assert!(sw_ctx_id < IDLE_SW_ID);
    debug_assert!(spec.instance < 64);
    let lo = DESC_VALID
        | DESC_MODE_LEGACY_64B
        | DESC_L3LLC_COHERENT
        | DESC_PRIVILEGE
        | (lrca as u64 & 0xFFFF_F000);
    let mut hi = ((sw_ctx_id as u64) & 0x7FF) << 5;
    hi |= ((spec.instance as u64) & 0x3F) << 16;
    hi |= spec.class.descriptor_value() << 29;
    (hi << 32) | lo
}

/// Build the RCS0 context descriptor (render class, instance 0 —
/// the historical form of [`context_descriptor_for`]).
pub fn context_descriptor(lrca: u32, sw_ctx_id: u16) -> u64 {
    context_descriptor_for(&RCS0_SPEC, lrca, sw_ctx_id)
}

/// Extract the LRCA (GGTT offset of the context image) from a
/// descriptor.
pub fn descriptor_lrca(desc: u64) -> u32 {
    (desc & 0xFFFF_F000) as u32
}

/// Extract the SW context id from a descriptor.
pub fn descriptor_sw_id(desc: u64) -> u16 {
    ((desc >> 37) & 0x7FF) as u16
}

/// Extract the engine instance (bits 48:53) from a descriptor.
pub fn descriptor_instance(desc: u64) -> u8 {
    ((desc >> 48) & 0x3F) as u8
}

/// Extract the engine class value (bits 61:63) from a
/// descriptor, as an [`EngineClass::descriptor_value`].
pub fn descriptor_class(desc: u64) -> u64 {
    (desc >> 61) & 0x7
}

// ── Register-state image (the LRC template) ─────────────────────
//
// The register state lives on page 1 of the context image (page
// 0 is hardware-owned context header space). It is shaped as a
// batch of MI_LOAD_REGISTER_IMM groups; the dword indices below
// are the PRM's "ENGINE CONTEXT" layout (KBL PRM Vol. 3 table,
// carried unchanged into Gen12), also used by i915's CTX_*
// defines. A (register, value) pair sits at (index, index + 1);
// per-submission updates patch only the value dwords of
// RING_HEAD / RING_TAIL / RING_BUFFER_START.

/// Byte offset of the register-state page inside the image.
pub const REG_STATE_PAGE_BYTE: u64 = GTT_PAGE_SIZE;
/// `CTX_LRI_HEADER_0` dword index.
pub const CTX_LRI_HEADER_0: usize = 0x01;
/// `CTX_CONTEXT_CONTROL` pair index.
pub const CTX_CONTEXT_CONTROL: usize = 0x02;
/// `CTX_RING_HEAD` pair index.
pub const CTX_RING_HEAD: usize = 0x04;
/// `CTX_RING_TAIL` pair index.
pub const CTX_RING_TAIL: usize = 0x06;
/// `CTX_RING_BUFFER_START` pair index.
pub const CTX_RING_BUFFER_START: usize = 0x08;
/// `CTX_RING_BUFFER_CONTROL` pair index.
pub const CTX_RING_BUFFER_CONTROL: usize = 0x0A;
/// `CTX_BB_HEAD_U` pair index.
pub const CTX_BB_HEAD_U: usize = 0x0C;
/// `CTX_BB_HEAD_L` pair index.
pub const CTX_BB_HEAD_L: usize = 0x0E;
/// `CTX_BB_STATE` pair index.
pub const CTX_BB_STATE: usize = 0x10;
/// `CTX_BB_PER_CTX_PTR` pair index.
pub const CTX_BB_PER_CTX_PTR: usize = 0x12;
/// `CTX_RCS_INDIRECT_CTX` pair index.
pub const CTX_RCS_INDIRECT_CTX: usize = 0x14;
/// `CTX_RCS_INDIRECT_CTX_OFFSET` pair index.
pub const CTX_RCS_INDIRECT_CTX_OFFSET: usize = 0x16;
/// `CTX_LRI_HEADER_1` dword index.
pub const CTX_LRI_HEADER_1: usize = 0x21;
/// `CTX_CTX_TIMESTAMP` pair index.
pub const CTX_CTX_TIMESTAMP: usize = 0x22;
/// `CTX_PDP3_UDW` pair index (PDP pairs run 3,2,1,0 descending).
pub const CTX_PDP3_UDW: usize = 0x24;
/// `CTX_LRI_HEADER_2` dword index.
pub const CTX_LRI_HEADER_2: usize = 0x41;
/// `CTX_R_PWR_CLK_STATE` pair index.
pub const CTX_R_PWR_CLK_STATE: usize = 0x42;
/// `CTX_END` dword index — the template's terminating dword.
pub const CTX_END: usize = 0xB9;
/// Gen12 non-render context restore terminator.
pub const CTX_XCS_END: usize = 0x34;
/// Total template dwords (indices `0..CTX_END` inclusive).
pub const REG_STATE_DWORDS: usize = CTX_END + 1;

/// `CONTEXT_CONTROL` value written into every context image:
/// masked-bit encoding — restore-inhibit *disabled* (the image
/// is fully self-initialised by this driver, so restoring it is
/// well-defined) and sync-context-switch *inhibited* (matches
/// the i915 template for execlists contexts).
pub const CTX_CONTROL_VALUE: u32 = {
    let restore_inhibit = 1u32 << 0;
    let inhibit_syn_ctx_switch = 1u32 << 3;
    (restore_inhibit << 16) | (inhibit_syn_ctx_switch << 16) | inhibit_syn_ctx_switch
};

/// `RING_CTL` value for a ring of `ring_bytes` (power of two,
/// page multiple): bit 0 = enable, bits20:12 = byte size minus one page.
pub const fn ring_ctl_value(ring_bytes: u32) -> u32 {
    (ring_bytes.wrapping_sub(4096) & 0x001f_f000) | 1
}

/// Build the register-state template for a fresh context on
/// the engine `spec` names, whose ring lives at GGTT offset
/// `ring_ggtt` with size `ring_bytes`. Everything the hardware
/// restores on first submission that this driver has an opinion
/// about is set here; the PDP pairs are zero (GGTT addressing —
/// PPGTT is #1012), the batch-head pairs are zero, and the
/// workaround-batch pointers are zero (no WA batches in this
/// lane).
///
/// The dword layout is engine-independent (the PRM ENGINE
/// CONTEXT table); the register *addresses* in the pairs are
/// the engine's own (`spec.base` + the shared offsets). The one
/// structural difference is the extended render groups:
/// `R_PWR_CLK_STATE` and the extended register state exist only in
/// render-class templates. XCS terminates after the PDP group.
pub fn build_reg_state_for(
    spec: &EngineSpec,
    ring_ggtt: u32,
    ring_bytes: u32,
) -> [u32; REG_STATE_DWORDS] {
    let b = spec.base;
    let mut r = [0u32; REG_STATE_DWORDS];
    // Source-cited Gen12 layout (MIT intel_lrc.c gen12_{r,x}cs_offsets).
    // These are engine-relative register offsets; the CS-MMIO selector
    // makes hardware interpret them relative to the engine block.
    const RELATIVE: u32 = 1 << 19;
    let first = [
        0x244, 0x34, 0x30, 0x38, 0x3c, 0x168, 0x140, 0x110, 0x1c0, 0x1c4, 0x1c8, 0x180, 0x2b4,
    ];
    r[CTX_LRI_HEADER_0] = mi_load_register_imm(13, true) | RELATIVE;
    for (i, offset) in first.iter().enumerate() {
        r[2 + i * 2] = b as u32 + offset;
    }
    r[CTX_CONTEXT_CONTROL + 1] = CTX_CONTROL_VALUE;
    r[CTX_RING_BUFFER_START + 1] = ring_ggtt;
    r[CTX_RING_BUFFER_CONTROL + 1] = ring_ctl_value(ring_bytes);
    r[CTX_LRI_HEADER_1] = mi_load_register_imm(9, true) | RELATIVE;
    r[CTX_CTX_TIMESTAMP] = (b + 0x3a8) as u32;
    for i in 0..4u32 {
        let at = CTX_PDP3_UDW + i as usize * 4;
        r[at] = ring_pdp_udw_at(b, 3 - i) as u32;
        r[at + 2] = ring_pdp_ldw_at(b, 3 - i) as u32;
    }
    if !spec.has_pwr_clk_state() {
        r[CTX_XCS_END] = MI_BATCH_BUFFER_END | 1;
        return r;
    }
    r[0x34] = mi_load_register_imm(3, true) | RELATIVE;
    for (i, offset) in [0x1b0, 0x5a8, 0x5ac].iter().enumerate() {
        r[0x35 + i * 2] = b as u32 + offset;
    }
    r[CTX_LRI_HEADER_2] = mi_load_register_imm(1, false) | RELATIVE;
    r[CTX_R_PWR_CLK_STATE] = R_PWR_CLK_STATE as u32;
    // Six restore slots for CTX_WA_PTR repeat 0x588, followed by the
    // remaining per-context register image. Values start zeroed.
    const FINAL: [u32; 51] = [
        0x588, 0x588, 0x588, 0x588, 0x588, 0x588, 0x28, 0x9c, 0xc0, 0x178, 0x17c, 0x358, 0x170,
        0x150, 0x154, 0x158, 0x41c, 0x600, 0x604, 0x608, 0x60c, 0x610, 0x614, 0x618, 0x61c, 0x620,
        0x624, 0x628, 0x62c, 0x630, 0x634, 0x638, 0x63c, 0x640, 0x644, 0x648, 0x64c, 0x650, 0x654,
        0x658, 0x65c, 0x660, 0x664, 0x668, 0x66c, 0x670, 0x674, 0x678, 0x67c, 0x68, 0x84,
    ];
    r[0x51] = mi_load_register_imm(51, true) | RELATIVE;
    for (i, offset) in FINAL.iter().enumerate() {
        r[0x52 + i * 2] = b as u32 + offset;
    }
    r[CTX_END] = MI_BATCH_BUFFER_END | 1;
    r
}

/// Build the RCS0 register-state template (the historical form
/// of [`build_reg_state_for`]).
pub fn build_reg_state(ring_ggtt: u32, ring_bytes: u32) -> [u32; REG_STATE_DWORDS] {
    build_reg_state_for(&RCS0_SPEC, ring_ggtt, ring_bytes)
}

// ── Context status buffer (Gen12 format) ────────────────────────

/// Dword index of the first CSB entry inside the engine status
/// page (i915 `I915_HWS_CSB_BUF0_INDEX`).
pub const CSB_BUF0_DWORD: u64 = 0x10;
/// Dword index of the CSB write pointer inside the status page
/// (i915 `CNL_HWS_CSB_WRITE_INDEX`, the Gen11+ location).
pub const CSB_WRITE_DWORD: u64 = 0x2F;
/// Number of CSB entries the Gen11+ hardware rotates through
/// (i915 `GEN11_CSB_ENTRIES`).
pub const CSB_ENTRIES: u8 = 12;
/// Byte offset of the CSB in the status page.
pub const CSB_BUF_BYTE: u64 = CSB_BUF0_DWORD * 4;
/// Byte offset of the CSB write pointer in the status page.
pub const CSB_WRITE_BYTE: u64 = CSB_WRITE_DWORD * 4;

/// One raw Gen12 CSB entry (two dwords as the hardware writes
/// them into the status page).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CsbEntry {
    /// Low dword: switch flags + the context switched *to*.
    pub lower: u32,
    /// High dword: switch detail + the context switched *away*.
    pub upper: u32,
}

impl CsbEntry {
    /// Bit 0 of the low dword — the engine switched to a new
    /// submission queue (the preemption marker on Gen12).
    pub fn switched_to_new_queue(&self) -> bool {
        self.lower & 0x1 != 0
    }
    /// SW context id (low dword bits 25:15) switched *to*.
    pub fn to_sw_id(&self) -> u16 {
        ((self.lower >> 15) & 0x7FF) as u16
    }
    /// SW context id (high dword bits 25:15) switched *away from*.
    pub fn away_sw_id(&self) -> u16 {
        ((self.upper >> 15) & 0x7FF) as u16
    }
    /// Context switch detail (high dword bits 3:0):
    /// 0 = context complete, 5 = context preempted, 1..=4 = wait
    /// events this driver never arms.
    pub fn switch_detail(&self) -> u32 {
        self.upper & 0xF
    }
    /// The switched-to id names a real context.
    pub fn to_valid(&self) -> bool {
        self.to_sw_id() != IDLE_SW_ID
    }
    /// The switched-away id names a real context.
    pub fn away_valid(&self) -> bool {
        self.away_sw_id() != IDLE_SW_ID
    }
}

/// The scheduling meaning of one CSB entry, mirroring the
/// Gen12 parse the i915 tasklet performs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CsbStep {
    /// Idle → context: the pending ports became active.
    Promote,
    /// The active context was preempted by a new queue.
    Preempt,
    /// The active context ran to its submitted tail and idled.
    Complete,
    /// Wait events and empty transitions: recorded, not acted on.
    Nop,
}

/// Classify one entry. `any_active` is whether the driver
/// currently believes a context occupies the engine — a
/// completion is only meaningful against an active context.
pub fn csb_step(entry: &CsbEntry, any_active: bool) -> CsbStep {
    if !entry.away_valid() && entry.to_valid() {
        return CsbStep::Promote;
    }
    if entry.switched_to_new_queue() && entry.away_valid() {
        return CsbStep::Preempt;
    }
    if entry.switch_detail() != 0 {
        // Wait-on-semaphore / sync-flip / vblank events (detail
        // 1..=4) are never armed by this driver, and a bare
        // detail-5 without the new-queue bit is the
        // preempt-to-idle form i915 also declines to handle.
        return CsbStep::Nop;
    }
    if any_active && entry.away_valid() {
        return CsbStep::Complete;
    }
    CsbStep::Nop
}

// ── Errors ──────────────────────────────────────────────────────

/// Failure modes of the submission path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// The handle does not name a live context (bad slot, or a
    /// stale generation from before a destroy/recreate cycle).
    UnknownContext,
    /// The context is loaded on the engine (pending or active
    /// ports, or requests in flight). This driver never patches
    /// a context image the hardware may be restoring or saving;
    /// the caller retries after completion drains it.
    ContextBusy,
    /// The ring has no room for the submission prologue.
    RingFull,
    /// The engine submission queue is at capacity.
    QueueFull,
    /// The context table is at capacity.
    TooManyContexts,
    /// A batch did not end with `MI_BATCH_BUFFER_END`, was
    /// empty, or was misaligned.
    BatchInvalid,
    /// GGTT arena space or host frames exhausted.
    OutOfMemory,
    /// `wait_seqno` budget expired before the breadcrumb landed.
    Timeout,
    /// Production glue only: no Intel controller has been
    /// probed, or it is not a Gen12 part.
    NoEngine,
    /// A PPGTT root physical address failed validation
    /// (unaligned, or outside the supported 46-bit address field) at
    /// [`RcsEngine::attach_ppgtt`].
    InvalidPpgttRoot,
    /// Production glue only: the render forcewake domain
    /// could not be acquired for a submission (ack timeout) —
    /// nothing was programmed. See
    /// [`crate::intel_gpu_forcewake`].
    Forcewake,
    /// Production glue only: submissions are gated off by
    /// power management (suspend in progress or device
    /// suspended) — nothing was programmed. See
    /// [`crate::intel_gpu_pm`].
    Suspended,
    /// A VA batch was submitted to a context with no PPGTT root
    /// attached ([`RcsEngine::submit_ppgtt`]).
    PpgttNotAttached,
}

// ── GPU-memory backing seam ─────────────────────────────────────
//
// Everything the submission path touches — context images,
// rings, status pages, batches — is a GGTT-backed object the CPU
// also reads and writes. Production backs them with host frames
// mapped into the GGTT; fixtures back them with byte vectors and
// a fake allocator, so the whole hardware conversation runs
// without a BAR. The engine is generic over the allocator for
// exactly this reason.

/// A CPU-addressable, GGTT-mapped allocation.
pub trait GpuBacking {
    /// GGTT offset of the allocation's first page.
    fn ggtt_offset(&self) -> u32;
    /// Size in 4 KiB pages.
    fn size_pages(&self) -> u32;
    /// Read the dword at byte offset `byte_off` (must be
    /// 4-byte aligned and inside the allocation).
    fn read32(&self, byte_off: u64) -> u32;
    /// Write the dword at byte offset `byte_off`.
    fn write32(&self, byte_off: u64, val: u32);
    /// Zero the whole allocation.
    fn zero_fill(&self) {
        let bytes = self.size_pages() as u64 * GTT_PAGE_SIZE;
        let mut off = 0;
        while off < bytes {
            self.write32(off, 0);
            off += 4;
        }
    }
}

/// Source of GGTT-backed allocations. The accounting counters
/// exist so fixtures can assert create/destroy balance exactly.
pub trait GpuAllocator {
    /// The backing type this allocator hands out.
    type Backing: GpuBacking;
    /// Allocate `pages` 4 KiB pages, zero-filled.
    fn alloc(&mut self, pages: u32) -> Result<Self::Backing, SubmitError>;
    /// Release an allocation back to the arena.
    fn free(&mut self, backing: Self::Backing);
    /// Live allocation count.
    fn live_allocations(&self) -> usize;
    /// Live allocated pages.
    fn live_pages(&self) -> u32;
}

// ── Production backing: host frames in the GGTT ─────────────────

/// GGTT window reserved for submission objects. The scanout
/// mapping lives at 16 MiB in [`crate::intel_gpu_gtt`]; the
/// arena starts at 256 MiB — far from the scanout, far below
/// the 4 GiB LRCA ceiling, and large enough for every context,
/// ring and batch this driver will hold at once.
pub const GGTT_ARENA_BASE: u32 = 0x1000_0000;
/// Arena size: 16 MiB of GGTT (4096 pages).
pub const GGTT_ARENA_PAGES: u32 = 4096;

/// A production allocation: host frames the CPU reaches through
/// the kernel direct map and the GPU reaches through the GGTT.
pub struct FrameBacking {
    ggtt: u32,
    pages: u32,
    frames: Vec<narf_memory::frame::PhysFrame>,
}

impl core::fmt::Debug for FrameBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameBacking")
            .field("ggtt_offset", &self.ggtt)
            .field("pages", &self.pages)
            .field("frames", &self.frames.len())
            .finish()
    }
}

impl FrameBacking {
    /// Raw pointer to the dword at `byte_off` inside the backing.
    ///
    /// # Safety
    /// `byte_off` must be 4-byte aligned, inside the allocation,
    /// and not straddle a page boundary (guaranteed for aligned
    /// dword offsets, since pages are 4 KiB).
    unsafe fn dword_ptr(&self, byte_off: u64) -> *mut u32 {
        let page = (byte_off / GTT_PAGE_SIZE) as usize;
        let within = byte_off % GTT_PAGE_SIZE;
        debug_assert!(page < self.frames.len());
        debug_assert!(within % 4 == 0 && within <= GTT_PAGE_SIZE - 4);
        let base = self.frames[page].start_address().kernel_mut_ptr::<u8>();
        // SAFETY: `page` indexes a frame this backing owns and
        // `within` is an in-page dword offset, so the pointer
        // lands inside that frame's direct-map page.
        unsafe { base.add(within as usize) as *mut u32 }
    }
}

impl GpuBacking for FrameBacking {
    fn ggtt_offset(&self) -> u32 {
        self.ggtt
    }
    fn size_pages(&self) -> u32 {
        self.pages
    }
    fn read32(&self, byte_off: u64) -> u32 {
        // SAFETY: callers pass in-allocation aligned offsets
        // (ring / image / status accesses are all dword slots
        // inside page-multiple allocations). Volatile because
        // the GPU writes some of this memory (CSB, breadcrumbs).
        unsafe { core::ptr::read_volatile(self.dword_ptr(byte_off) as *const u32) }
    }
    fn write32(&self, byte_off: u64, val: u32) {
        // SAFETY: same contract as `read32`.
        unsafe { core::ptr::write_volatile(self.dword_ptr(byte_off), val) }
    }
}

/// First-fit GGTT arena + frame allocator (production
/// [`GpuAllocator`]). Owns the BAR0 handle for GGTT PTE writes;
/// PTE programming follows [`crate::intel_gpu_gtt`]'s pattern
/// (64-bit PTE as two 32-bit writes into the array at BAR0 +
/// 8 MiB), with engine PTEs (RW, LLC-cached).
pub struct GgttArena {
    bar: narf_bus::bar::MmioRegion,
    free_list: Vec<(u32, u32)>,
    live: usize,
    live_pages: u32,
    /// GGTT virtual size implied by the BAR length (0 = the
    /// BAR length is unknown to this handle, checks skipped —
    /// production always constructs over the probed BAR).
    ggtt_va_size: u64,
}

impl core::fmt::Debug for GgttArena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GgttArena")
            .field("free_blocks", &self.free_list.len())
            .field("live_allocations", &self.live)
            .field("live_pages", &self.live_pages)
            .finish()
    }
}

impl GgttArena {
    /// Create an arena covering [`GGTT_ARENA_BASE`] for
    /// [`GGTT_ARENA_PAGES`] pages over the BAR0 window `bar`.
    pub fn new(bar: narf_bus::bar::MmioRegion) -> Self {
        let ggtt_va_size = ggtt_va_size(bar.len);
        // The arena window is a fixed reservation inside the
        // GGTT; on any real Gen12 BAR (16 MiB -> 4 GiB GGTT) it
        // fits with room to spare. If a part ever shows a BAR
        // too small for it, `alloc` refuses rather than writing
        // PTEs past the window the BAR implies.
        debug_assert!(
            ggtt_va_size == 0
                || GGTT_ARENA_BASE as u64 + GGTT_ARENA_PAGES as u64 * GTT_PAGE_SIZE <= ggtt_va_size
        );
        Self {
            bar,
            free_list: alloc::vec![(GGTT_ARENA_BASE, GGTT_ARENA_PAGES)],
            live: 0,
            live_pages: 0,
            ggtt_va_size,
        }
    }

    /// Write one GGTT PTE (or zero to invalidate) at `ggtt_off`.
    fn write_pte(&self, ggtt_off: u32, pte: u64) {
        let pte_byte = GGTT_ARRAY_BASE + (ggtt_off as u64 / GTT_PAGE_SIZE) * 8;
        // SAFETY: `self.bar` is the probe-mapped BAR0 owned by
        // this driver; `pte_byte` is an 8-byte-aligned slot inside
        // the GGTT array half of BAR0 for any in-arena offset —
        // `alloc` has bounds-checked the arena against the GGTT
        // size this BAR implies before any PTE is written.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            self.bar.write32(pte_byte, (pte & 0xFFFF_FFFF) as u32);
            self.bar.write32(pte_byte + 4, (pte >> 32) as u32);
        }
    }

    /// Posting flush for a burst of arena PTE writes: fence,
    /// then read back the slot at `last_ggtt_off` so the writes
    /// are visible before the backing is handed to an engine.
    fn flush_pte_writes(&self, last_ggtt_off: u32) {
        compiler_fence(Ordering::SeqCst);
        let pte_byte = GGTT_ARRAY_BASE + (last_ggtt_off as u64 / GTT_PAGE_SIZE) * 8;
        // SAFETY: same BAR ownership and in-arena argument as
        // `write_pte`; a GGTT array read has no side effect.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            let _ = self.bar.read32(pte_byte);
        }
    }
}

impl GpuAllocator for GgttArena {
    type Backing = FrameBacking;

    fn alloc(&mut self, pages: u32) -> Result<FrameBacking, SubmitError> {
        if pages == 0 {
            return Err(SubmitError::OutOfMemory);
        }
        // Bounds discipline (the GgttArena form of
        // intel_gpu_gtt::check_ggtt_range): never hand out —
        // and therefore never write PTEs for — a range past the
        // GGTT window the BAR length implies. Applied per
        // allocation below, once the slot is known.
        // First-fit over the free list.
        let mut slot = None;
        for (i, &(off, len)) in self.free_list.iter().enumerate() {
            if len >= pages {
                slot = Some((i, off, len));
                break;
            }
        }
        let (i, off, len) = slot.ok_or(SubmitError::OutOfMemory)?;
        if self.ggtt_va_size != 0 && off as u64 + pages as u64 * GTT_PAGE_SIZE > self.ggtt_va_size {
            return Err(SubmitError::OutOfMemory);
        }
        // Secure the frames before carving the block, so a frame
        // failure leaves the arena untouched.
        let mut frames = Vec::with_capacity(pages as usize);
        for _ in 0..pages {
            match narf_memory::frame::alloc_frame() {
                Ok(f) => frames.push(f),
                Err(_) => {
                    for f in frames.drain(..) {
                        narf_memory::frame::free_frame(f);
                    }
                    return Err(SubmitError::OutOfMemory);
                }
            }
        }
        if len == pages {
            self.free_list.remove(i);
        } else {
            self.free_list[i] = (off + pages * GTT_PAGE_SIZE as u32, len - pages);
        }
        let backing = FrameBacking {
            ggtt: off,
            pages,
            frames,
        };
        for (p, frame) in backing.frames.iter().enumerate() {
            let pte = encode_scanout_pte(frame.start_address().raw(), PatSlot::Slot0)
                .map_err(|_| SubmitError::OutOfMemory)?;
            self.write_pte(off + (p as u32) * GTT_PAGE_SIZE as u32, pte);
        }
        if pages > 0 {
            self.flush_pte_writes(off + (pages - 1) * GTT_PAGE_SIZE as u32);
        }
        backing.zero_fill();
        self.live += 1;
        self.live_pages += pages;
        Ok(backing)
    }

    fn free(&mut self, backing: FrameBacking) {
        for p in 0..backing.pages {
            self.write_pte(backing.ggtt + p * GTT_PAGE_SIZE as u32, 0);
        }
        if backing.pages > 0 {
            self.flush_pte_writes(backing.ggtt + (backing.pages - 1) * GTT_PAGE_SIZE as u32);
        }
        for f in backing.frames {
            narf_memory::frame::free_frame(f);
        }
        self.live -= 1;
        self.live_pages -= backing.pages;
        // Reinsert and coalesce with neighbours.
        self.free_list.push((backing.ggtt, backing.pages));
        self.free_list.sort_by_key(|&(off, _)| off);
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.free_list.len());
        for (off, len) in self.free_list.drain(..) {
            if let Some(last) = merged.last_mut() {
                let last_end = last.0 + last.1 * GTT_PAGE_SIZE as u32;
                if last_end == off {
                    last.1 += len;
                    continue;
                }
            }
            merged.push((off, len));
        }
        self.free_list = merged;
    }

    fn live_allocations(&self) -> usize {
        self.live
    }
    fn live_pages(&self) -> u32 {
        self.live_pages
    }
}

/// A cloneable handle to one [`GgttArena`]. Production runs
/// several engines (RCS + the media engines) over the single
/// GGTT; each engine owns its allocator by value, so the one
/// physical arena is shared through this lock-wrapper —
/// engines hold clones, and the arena itself stays the single
/// first-fit allocator, so two engines can never be handed
/// the same GGTT offset.
#[derive(Clone)]
pub struct SharedArena {
    inner: Arc<narf_lib::sync::IrqSafeSpinLock<GgttArena>>,
}

impl core::fmt::Debug for SharedArena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedArena").finish_non_exhaustive()
    }
}

impl SharedArena {
    /// Wrap an arena for sharing between engines.
    pub fn new(arena: GgttArena) -> Self {
        Self {
            inner: Arc::new(narf_lib::sync::IrqSafeSpinLock::new(arena)),
        }
    }
}

impl GpuAllocator for SharedArena {
    type Backing = FrameBacking;

    fn alloc(&mut self, pages: u32) -> Result<FrameBacking, SubmitError> {
        self.inner.lock().alloc(pages)
    }
    fn free(&mut self, backing: FrameBacking) {
        self.inner.lock().free(backing)
    }
    fn live_allocations(&self) -> usize {
        self.inner.lock().live_allocations()
    }
    fn live_pages(&self) -> u32 {
        self.inner.lock().live_pages()
    }
}

// ── Ring / context / engine ─────────────────────────────────────

/// Ring size per context: 128 KiB (the i915 default), 32 pages.
pub const RING_PAGES: u32 = 32;
/// Ring size in bytes (power of two — head/tail wrap by mask).
pub const RING_BYTES: u32 = RING_PAGES * 4096;
/// Pages allocated per context image. An allocation *bound*
/// above the Gen12 RCS hardware image size (see module docs).
pub const RCS_IMAGE_PAGES: u32 = 48;
/// Maximum simultaneous contexts on the engine.
pub const MAX_CONTEXTS: usize = 64;
/// Maximum requests waiting for a free execlist port.
pub const MAX_QUEUED_REQUESTS: usize = 64;
/// Byte offset of the breadcrumb sequence number inside a
/// context's hardware status page.
pub const HWSP_SEQNO_BYTE: u64 = 0;

/// External context handle: slot index in the low half, slot
/// generation in the high half. A handle captured before a
/// destroy/recreate cycle names a dead generation and is
/// rejected with [`SubmitError::UnknownContext`] instead of
/// silently aliasing the new context in the slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ContextId(pub u32);

impl ContextId {
    /// Pack a slot + generation into a handle.
    pub fn pack(slot: u32, generation: u32) -> Self {
        Self((generation << 16) | (slot & 0xFFFF))
    }
    /// Slot index portion.
    pub fn slot(self) -> u32 {
        self.0 & 0xFFFF
    }
    /// Generation portion.
    pub fn generation(self) -> u32 {
        self.0 >> 16
    }
}

/// A batch buffer ready to submit: GGTT-backed dwords whose
/// last dword is `MI_BATCH_BUFFER_END` (checked by
/// [`RcsEngine::write_batch`]). Ownership moves into the engine
/// at submit; the allocation is freed when the request retires.
pub struct BatchBuf<A: GpuAllocator> {
    backing: A::Backing,
    dwords: u32,
}

impl<A: GpuAllocator> BatchBuf<A> {
    /// GGTT offset of the batch.
    pub fn ggtt_offset(&self) -> u32 {
        self.backing.ggtt_offset()
    }
    /// Batch length in dwords.
    pub fn len_dwords(&self) -> u32 {
        self.dwords
    }
}

impl<A: GpuAllocator> core::fmt::Debug for BatchBuf<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchBuf")
            .field("ggtt_offset", &self.backing.ggtt_offset())
            .field("dwords", &self.dwords)
            .finish()
    }
}

/// A retired request, as returned by
/// [`RcsEngine::poll_completions`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompletedRequest {
    /// Context the request ran on.
    pub ctx: ContextId,
    /// Breadcrumb sequence number the request carried.
    pub seqno: u32,
    /// Engine-wide request id returned by `submit`.
    pub request: u64,
}

/// Driver-side ring bookkeeping for one context. Offsets are
/// byte offsets inside the ring, always masked into
/// `[0, RING_BYTES)`.
#[derive(Copy, Clone, Debug)]
struct RingState {
    head: u32,
    tail: u32,
}

/// Append `dwords` to the ring image in `mem`, padding the tail
/// end with `MI_NOOP` when the command would straddle the wrap.
/// Keeps an 8-byte slack so head never aliases tail (the same
/// reserve the hardware's WA-tail handling assumes).
fn ring_emit<B: GpuBacking>(
    mem: &B,
    ring: &mut RingState,
    dwords: &[u32],
) -> Result<(), SubmitError> {
    let need = (dwords.len() as u32) * 4;
    let used = ring.tail.wrapping_sub(ring.head) & (RING_BYTES - 1);
    if need > RING_BYTES - used - 8 {
        return Err(SubmitError::RingFull);
    }
    if ring.tail + need > RING_BYTES {
        let mut off = ring.tail;
        while off < RING_BYTES {
            mem.write32(off as u64, MI_NOOP);
            off += 4;
        }
        ring.tail = 0;
    }
    for (i, dw) in dwords.iter().enumerate() {
        mem.write32((ring.tail + (i as u32) * 4) as u64, *dw);
    }
    ring.tail = (ring.tail + need) & (RING_BYTES - 1);
    Ok(())
}

/// One live context: its image, ring, status page and the
/// driver's bookkeeping for both.
struct RcsContext<A: GpuAllocator> {
    slot: u32,
    generation: u32,
    sw_id: u16,
    descriptor: u64,
    image: A::Backing,
    ring_mem: A::Backing,
    hwsp: A::Backing,
    ring: RingState,
    next_seqno: u32,
    last_completed_seqno: u32,
    /// PPGTT root programmed into the image's PDP0 pair, when
    /// one is attached (see [`RcsEngine::attach_ppgtt`]). The
    /// tables themselves are owned by the
    /// [`crate::intel_gpu_ppgtt::Ppgtt`] that produced the
    /// root; the engine only carries the address.
    ppgtt_root: Option<u64>,
}

impl<A: GpuAllocator> core::fmt::Debug for RcsContext<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RcsContext")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .field("sw_id", &self.sw_id)
            .field("descriptor", &self.descriptor)
            .field("ring", &self.ring)
            .field("next_seqno", &self.next_seqno)
            .finish_non_exhaustive()
    }
}

/// A submitted request awaiting retirement.
struct Request<A: GpuAllocator> {
    ctx_slot: u32,
    ctx_gen: u32,
    seqno: u32,
    id: u64,
    batch: BatchBuf<A>,
}

/// An execlists engine: context table, two submission ports,
/// CSB drain. Instantiated for RCS0 by default; the media
/// engines in [`crate::intel_gpu_media`] instantiate the same
/// machinery over their own [`EngineSpec`] via
/// [`RcsEngine::with_spec`]. Generic over the MMIO window and
/// the GGTT allocator so fixtures can drive the full protocol
/// against a modelled GPU.
pub struct RcsEngine<M: MmioWindow, A: GpuAllocator> {
    spec: EngineSpec,
    mmio: M,
    alloc: A,
    status: A::Backing,
    csb_head: u8,
    contexts: Vec<Option<RcsContext<A>>>,
    generations: Vec<u32>,
    queue: VecDeque<Request<A>>,
    inflight: Vec<Request<A>>,
    pending: [Option<u32>; 2],
    active: [Option<u32>; 2],
    next_request_id: u64,
    spurious_csb: u32,
}

impl<M: MmioWindow, A: GpuAllocator> core::fmt::Debug for RcsEngine<M, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RcsEngine")
            .field("engine", &self.spec.name)
            .field("status_ggtt", &self.status.ggtt_offset())
            .field("csb_head", &self.csb_head)
            .field("contexts", &self.contexts.len())
            .field("queued", &self.queue.len())
            .field("inflight", &self.inflight.len())
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow, A: GpuAllocator> RcsEngine<M, A> {
    /// Bring up the RCS0 engine (render class, base 0x2000).
    pub fn new(mmio: M, alloc: A) -> Result<Self, SubmitError> {
        Self::with_spec(RCS0_SPEC, mmio, alloc)
    }

    /// Bring up the engine `spec` names: allocate the engine
    /// status page and program that engine's `RING_HWS_PGA`,
    /// then adopt the hardware's current CSB write pointer so
    /// no stale entry is replayed.
    pub fn with_spec(spec: EngineSpec, mmio: M, mut alloc: A) -> Result<Self, SubmitError> {
        let status = alloc.alloc(1)?;
        mmio.write32(spec.hws_pga(), status.ggtt_offset());
        let head = ((status.read32(CSB_WRITE_BYTE) & 0xFF) as u8) % CSB_ENTRIES;
        Ok(Self {
            spec,
            mmio,
            alloc,
            status,
            csb_head: head,
            contexts: Vec::new(),
            generations: Vec::new(),
            queue: VecDeque::new(),
            inflight: Vec::new(),
            pending: [None, None],
            active: [None, None],
            next_request_id: 1,
            spurious_csb: 0,
        })
    }

    /// GGTT offset of the engine status page (the CSB page).
    pub fn status_ggtt(&self) -> u32 {
        self.status.ggtt_offset()
    }

    /// The identity of the engine this instance drives.
    pub fn spec(&self) -> EngineSpec {
        self.spec
    }

    /// Live-allocation accounting of the underlying arena
    /// (includes the engine status page).
    pub fn live_allocations(&self) -> usize {
        self.alloc.live_allocations()
    }

    /// CSB entries that named no live context, counted instead
    /// of acted on (a health signal, not an error).
    pub fn spurious_csb(&self) -> u32 {
        self.spurious_csb
    }

    fn context(&self, id: ContextId) -> Result<&RcsContext<A>, SubmitError> {
        match self.contexts.get(id.slot() as usize) {
            Some(Some(c)) if c.generation == id.generation() => Ok(c),
            _ => Err(SubmitError::UnknownContext),
        }
    }

    fn context_mut(&mut self, id: ContextId) -> Result<&mut RcsContext<A>, SubmitError> {
        match self.contexts.get_mut(id.slot() as usize) {
            Some(Some(c)) if c.generation == id.generation() => Ok(c),
            _ => Err(SubmitError::UnknownContext),
        }
    }

    fn slot_of_sw(&self, sw_id: u16) -> Option<u32> {
        self.contexts
            .iter()
            .flatten()
            .find(|c| c.sw_id == sw_id)
            .map(|c| c.slot)
    }

    /// Create a context: allocate its image / ring / status
    /// page, build the register-state template, and mint its
    /// descriptor. The context starts idle with an empty ring.
    pub fn create_context(&mut self) -> Result<ContextId, SubmitError> {
        let slot = match self.contexts.iter().position(|c| c.is_none()) {
            Some(i) => i,
            None => {
                if self.contexts.len() >= MAX_CONTEXTS {
                    return Err(SubmitError::TooManyContexts);
                }
                self.contexts.push(None);
                self.generations.push(1);
                self.contexts.len() - 1
            }
        };
        let image = self.alloc.alloc(self.spec.image_pages)?;
        let ring_mem = match self.alloc.alloc(RING_PAGES) {
            Ok(r) => r,
            Err(e) => {
                self.alloc.free(image);
                return Err(e);
            }
        };
        let hwsp = match self.alloc.alloc(1) {
            Ok(h) => h,
            Err(e) => {
                self.alloc.free(ring_mem);
                self.alloc.free(image);
                return Err(e);
            }
        };
        let template = build_reg_state_for(&self.spec, ring_mem.ggtt_offset(), RING_BYTES);
        for (i, dw) in template.iter().enumerate() {
            image.write32(REG_STATE_PAGE_BYTE + (i as u64) * 4, *dw);
        }
        let generation = self.generations[slot];
        let sw_id = (slot as u16) + 1;
        let descriptor = context_descriptor_for(&self.spec, image.ggtt_offset(), sw_id);
        self.contexts[slot] = Some(RcsContext {
            slot: slot as u32,
            generation,
            sw_id,
            descriptor,
            image,
            ring_mem,
            hwsp,
            ring: RingState { head: 0, tail: 0 },
            next_seqno: 1,
            last_completed_seqno: 0,
            ppgtt_root: None,
        });
        Ok(ContextId::pack(slot as u32, generation))
    }

    /// Destroy an idle context and reclaim its allocations.
    /// Refuses ([`SubmitError::ContextBusy`]) while the context
    /// occupies a port or has requests queued or in flight —
    /// the caller drains it via [`Self::poll_completions`]
    /// first. The slot generation advances, invalidating the
    /// handle.
    pub fn destroy_context(&mut self, id: ContextId) -> Result<(), SubmitError> {
        let slot = self.context(id)?.slot;
        if self.pending.contains(&Some(slot)) || self.active.contains(&Some(slot)) {
            return Err(SubmitError::ContextBusy);
        }
        if self.queue.iter().any(|r| r.ctx_slot == slot)
            || self.inflight.iter().any(|r| r.ctx_slot == slot)
        {
            return Err(SubmitError::ContextBusy);
        }
        let ctx = self.contexts[slot as usize]
            .take()
            .expect("validated live context");
        self.alloc.free(ctx.image);
        self.alloc.free(ctx.ring_mem);
        self.alloc.free(ctx.hwsp);
        let gen = &mut self.generations[slot as usize];
        *gen = gen.wrapping_add(1).max(1);
        Ok(())
    }

    /// Copy `dwords` into a fresh GGTT batch allocation. The
    /// batch must be non-empty and end with
    /// `MI_BATCH_BUFFER_END` — the engine appends its own
    /// breadcrumb after the batch *start*, so a batch that
    /// never ends would run the ring off into the breadcrumb
    /// stream.
    pub fn write_batch(&mut self, dwords: &[u32]) -> Result<BatchBuf<A>, SubmitError> {
        if dwords.is_empty() || dwords[dwords.len() - 1] != MI_BATCH_BUFFER_END {
            return Err(SubmitError::BatchInvalid);
        }
        let pages = (dwords.len() as u32).div_ceil(1024);
        let backing = self.alloc.alloc(pages)?;
        for (i, dw) in dwords.iter().enumerate() {
            backing.write32((i as u64) * 4, *dw);
        }
        Ok(BatchBuf {
            backing,
            dwords: dwords.len() as u32,
        })
    }

    /// Whether `slot` is loaded on the engine or has covered
    /// requests — the states in which patching its image would
    /// race the hardware.
    fn ctx_covered(&self, slot: u32) -> bool {
        self.pending.contains(&Some(slot))
            || self.active.contains(&Some(slot))
            || self.inflight.iter().any(|r| r.ctx_slot == slot)
    }

    /// Submit a batch on a context: emit the batch-start +
    /// breadcrumb prologue into its ring, advance the image
    /// tail, and queue the request for the next free port. The
    /// batch is addressed through the GGTT.
    ///
    /// The context must be *idle* (not loaded, nothing in
    /// flight) — see [`SubmitError::ContextBusy`]. Submitting
    /// further batches to a context that merely has *queued*
    /// requests is fine: they emit into the same ring and are
    /// covered together when the context is next loaded.
    /// Returns the engine-wide request id.
    pub fn submit(&mut self, id: ContextId, batch: BatchBuf<A>) -> Result<u64, SubmitError> {
        self.submit_inner(id, batch, false)
    }

    /// Submit a batch addressed through the context's PPGTT
    /// (the batch-start carries the PPGTT address-space
    /// indicator; see [`mi_batch_buffer_start_ppgtt`]).
    ///
    /// The batch allocation stays GGTT-backed, and the VA the
    /// engine is handed is the batch's GGTT offset: the caller
    /// must have mapped the batch's pages at that same VA in
    /// the attached PPGTT (identity placement — the natural
    /// layout over this driver's GGTT arena, whose offsets are
    /// stable VAs). The engine cannot verify the mapping; it
    /// only refuses ([`SubmitError::PpgttNotAttached`]) when no
    /// root is attached at all. Same idle discipline and return
    /// contract as [`Self::submit`].
    pub fn submit_ppgtt(&mut self, id: ContextId, batch: BatchBuf<A>) -> Result<u64, SubmitError> {
        match self.context(id) {
            Ok(c) if c.ppgtt_root.is_some() => {}
            Ok(_) => {
                self.alloc.free(batch.backing);
                return Err(SubmitError::PpgttNotAttached);
            }
            Err(e) => {
                self.alloc.free(batch.backing);
                return Err(e);
            }
        }
        self.submit_inner(id, batch, true)
    }

    fn submit_inner(
        &mut self,
        id: ContextId,
        batch: BatchBuf<A>,
        ppgtt_form: bool,
    ) -> Result<u64, SubmitError> {
        let (slot, generation) = match self.context(id) {
            Ok(c) => (c.slot, c.generation),
            Err(e) => {
                self.alloc.free(batch.backing);
                return Err(e);
            }
        };
        if self.ctx_covered(slot) {
            self.alloc.free(batch.backing);
            return Err(SubmitError::ContextBusy);
        }
        if self.queue.len() >= MAX_QUEUED_REQUESTS {
            self.alloc.free(batch.backing);
            return Err(SubmitError::QueueFull);
        }
        let request_id = self.next_request_id;
        let seqno = {
            let ctx = self.context_mut(id)?;
            let seqno = ctx.next_seqno;
            let start = if ppgtt_form {
                mi_batch_buffer_start_ppgtt(batch.backing.ggtt_offset() as u64)
            } else {
                mi_batch_buffer_start_ggtt(batch.backing.ggtt_offset() as u64)
            };
            let store =
                mi_store_dword_imm_ggtt(ctx.hwsp.ggtt_offset() as u64 + HWSP_SEQNO_BYTE, seqno);
            let mut prologue = [0u32; 7];
            prologue[..3].copy_from_slice(&start);
            prologue[3..].copy_from_slice(&store);
            if let Err(e) = ring_emit(&ctx.ring_mem, &mut ctx.ring, &prologue) {
                // End the mutable borrow of `self` held through
                // `ctx` so `self.alloc` is usable on this error
                // path. `ctx` is a reference, so nothing is (or
                // could be) dropped — consuming the binding is
                // what ends the borrow.
                let _ = ctx;
                self.alloc.free(batch.backing);
                return Err(e);
            }
            ctx.next_seqno = if seqno == u32::MAX { 1 } else { seqno + 1 };
            ctx.image.write32(
                REG_STATE_PAGE_BYTE + ((CTX_RING_TAIL + 1) as u64) * 4,
                ctx.ring.tail,
            );
            ctx.image.write32(
                REG_STATE_PAGE_BYTE + ((CTX_RING_HEAD + 1) as u64) * 4,
                ctx.ring.head,
            );
            seqno
        };
        self.next_request_id += 1;
        self.queue.push_back(Request {
            ctx_slot: slot,
            ctx_gen: generation,
            seqno,
            id: request_id,
            batch,
        });
        self.pump();
        Ok(request_id)
    }

    /// The last breadcrumb sequence number retired for a
    /// context (0 = none yet).
    pub fn last_completed_seqno(&self, id: ContextId) -> Result<u32, SubmitError> {
        Ok(self.context(id)?.last_completed_seqno)
    }

    /// The breadcrumb sequence number the hardware most
    /// recently wrote into a context's status page.
    pub fn hw_seqno(&self, id: ContextId) -> Result<u32, SubmitError> {
        let ctx = self.context(id)?;
        Ok(ctx.hwsp.read32(HWSP_SEQNO_BYTE))
    }

    /// The PPGTT root attached to a context, if any.
    pub fn ppgtt_root(&self, id: ContextId) -> Result<Option<u64>, SubmitError> {
        Ok(self.context(id)?.ppgtt_root)
    }

    /// Attach a PPGTT root (the PML4 physical address from
    /// [`crate::intel_gpu_ppgtt::Ppgtt::root_phys`]) to an idle
    /// context: the register-state image's PDP0 pair is patched
    /// to the raw root physical address in PDP0 (4-level mode),
    /// and PDP1–PDP3 are zeroed. In the 4-level walk the PDP0
    /// pair is the root slot — the single patch site flagged in
    /// spec §9 for first-silicon verification.
    ///
    /// Like every image patch in this engine, attaching refuses
    /// ([`SubmitError::ContextBusy`]) while the context is
    /// loaded or has work in flight: the hardware may be
    /// restoring or saving the image. Re-attaching a different
    /// root to an idle context replaces the old one; the tables
    /// behind either root stay owned by their `Ppgtt`.
    pub fn attach_ppgtt(&mut self, id: ContextId, root_phys: u64) -> Result<(), SubmitError> {
        encode_table_entry(root_phys).map_err(|_| SubmitError::InvalidPpgttRoot)?;
        if root_phys == 0 {
            return Err(SubmitError::InvalidPpgttRoot);
        }
        let slot = self.context(id)?.slot;
        if self.ctx_covered(slot) {
            return Err(SubmitError::ContextBusy);
        }
        let ctx = self.context_mut(id)?;
        Self::patch_pdp_values(&ctx.image, Some(root_phys));
        ctx.ppgtt_root = Some(root_phys);
        Ok(())
    }

    /// Detach a context's PPGTT root: all four PDP pairs in the
    /// image return to zero and the context addresses through
    /// the GGTT alone again. Same idle discipline as
    /// [`Self::attach_ppgtt`].
    pub fn detach_ppgtt(&mut self, id: ContextId) -> Result<(), SubmitError> {
        let slot = self.context(id)?.slot;
        if self.ctx_covered(slot) {
            return Err(SubmitError::ContextBusy);
        }
        let ctx = self.context_mut(id)?;
        Self::patch_pdp_values(&ctx.image, None);
        ctx.ppgtt_root = None;
        Ok(())
    }

    /// Write the PDP values into a context image's
    /// register-state page. Template layout (group 1): the four
    /// PDP pairs run PDP3, PDP2, PDP1, PDP0 at a 4-dword stride
    /// from [`CTX_PDP3_UDW`], each pair holding its UDW value at
    /// +1 and its LDW value at +3. `root` is the raw PML4
    /// physical address for PDP0; the other pairs are always zero in
    /// the 4-level model.
    fn patch_pdp_values<B: GpuBacking>(image: &B, root: Option<u64>) {
        for pair in 0..4u64 {
            let udw_val = CTX_PDP3_UDW as u64 + pair * 4 + 1;
            let ldw_val = udw_val + 2;
            let (hi, lo) = match (pair, root) {
                (3, Some(entry)) => ((entry >> 32) as u32, entry as u32),
                _ => (0, 0),
            };
            image.write32(REG_STATE_PAGE_BYTE + udw_val * 4, hi);
            image.write32(REG_STATE_PAGE_BYTE + ldw_val * 4, lo);
        }
    }

    /// Move queued work into the execlist ports when they are
    /// free: the first two distinct contexts in FIFO order are
    /// covered (all their queued requests move to in-flight and
    /// ride the image tail already written), then the ELSP
    /// doorbell is rung.
    fn pump(&mut self) {
        if self.pending.iter().any(|p| p.is_some()) || self.queue.is_empty() {
            return;
        }
        let first = self.queue[0].ctx_slot;
        let mut chosen = [Some(first), None];
        for r in self.queue.iter() {
            if r.ctx_slot != first {
                chosen[1] = Some(r.ctx_slot);
                break;
            }
        }
        let mut rest = VecDeque::with_capacity(self.queue.len());
        while let Some(r) = self.queue.pop_front() {
            if chosen.contains(&Some(r.ctx_slot)) {
                self.inflight.push(r);
            } else {
                rest.push_back(r);
            }
        }
        self.queue = rest;
        let desc = |slot: Option<u32>| match slot {
            Some(s) => {
                self.contexts[s as usize]
                    .as_ref()
                    .expect("queued request names a live context")
                    .descriptor
            }
            None => 0,
        };
        self.pending = chosen;
        self.elsp_write(desc(chosen[0]), desc(chosen[1]));
    }

    /// Write a descriptor pair to the ELSP in the hardware
    /// order — port 1 first, port 0 last; the port-0 low write
    /// is the doorbell. Followed by the posting read the PRM
    /// prescribes (ELSP is write-only, so a neighbouring status
    /// register is read instead).
    fn elsp_write(&mut self, port0: u64, port1: u64) {
        compiler_fence(Ordering::SeqCst);
        self.mmio.write32(self.spec.elsp(), (port1 >> 32) as u32);
        self.mmio.write32(self.spec.elsp(), port1 as u32);
        self.mmio.write32(self.spec.elsp(), (port0 >> 32) as u32);
        self.mmio.write32(self.spec.elsp(), port0 as u32);
        let _ = self.mmio.read32(self.spec.execlist_status());
    }

    /// Drain every CSB entry the hardware has published since
    /// the last call, retiring requests and freeing their batch
    /// allocations. Returns the completions in CSB order. Also
    /// pumps the ports afterwards, so a caller that only polls
    /// keeps the engine fed.
    /// Whether the engine has no work anywhere: nothing
    /// queued, nothing in flight, and no context in the
    /// pending or active execlists ports. Callers that need a
    /// quiesced engine (power management, #1015) drain via
    /// [`Self::poll_completions`] until this holds.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty()
            && self.inflight.is_empty()
            && self.pending.iter().all(|p| p.is_none())
            && self.active.iter().all(|a| a.is_none())
    }

    pub fn poll_completions(&mut self) -> Vec<CompletedRequest> {
        let mut done = Vec::new();
        let tail = ((self.status.read32(CSB_WRITE_BYTE) & 0xFF) as u8) % CSB_ENTRIES;
        let mut head = self.csb_head;
        while head != tail {
            head = (head + 1) % CSB_ENTRIES;
            let base = CSB_BUF_BYTE + (head as u64) * 8;
            let entry = CsbEntry {
                lower: self.status.read32(base),
                upper: self.status.read32(base + 4),
            };
            self.process_csb(entry, &mut done);
        }
        self.csb_head = head;
        self.pump();
        done
    }

    fn process_csb(&mut self, entry: CsbEntry, done: &mut Vec<CompletedRequest>) {
        let any_active = self.active.iter().any(|a| a.is_some());
        match csb_step(&entry, any_active) {
            CsbStep::Promote => {
                // A promote names the pair most recently written
                // to the ELSP. If the ports are already empty the
                // entry is a replay (or a duplicate posted by a
                // confused peer); adopting the empty pair would
                // clobber the genuinely active contexts, so it is
                // recorded as a no-op instead.
                if self.pending.iter().any(|p| p.is_some()) {
                    self.active = self.pending;
                    self.pending = [None, None];
                }
            }
            CsbStep::Preempt => {
                if entry.away_valid() {
                    if let Some(slot) = self.slot_of_sw(entry.away_sw_id()) {
                        self.unschedule(slot);
                    } else {
                        self.spurious_csb += 1;
                    }
                }
                self.active = self.pending;
                self.pending = [None, None];
            }
            CsbStep::Complete => {
                if let Some(slot) = self.slot_of_sw(entry.away_sw_id()) {
                    self.retire(slot, done);
                } else {
                    self.spurious_csb += 1;
                }
            }
            CsbStep::Nop => {}
        }
    }

    /// A preempted context keeps its ring contents and image
    /// tail; its covered requests return to the queue front so
    /// the next pump reloads it.
    fn unschedule(&mut self, slot: u32) {
        for a in self.active.iter_mut() {
            if *a == Some(slot) {
                *a = None;
            }
        }
        let mut back = Vec::new();
        let mut keep = Vec::new();
        for r in self.inflight.drain(..) {
            if r.ctx_slot == slot {
                back.push(r);
            } else {
                keep.push(r);
            }
        }
        self.inflight = keep;
        for r in back.into_iter().rev() {
            self.queue.push_front(r);
        }
    }

    /// A completed context ran its ring to the submitted tail:
    /// retire its in-flight requests in order, free their
    /// batches, and sync the driver's ring head from the image
    /// the hardware saved.
    fn retire(&mut self, slot: u32, done: &mut Vec<CompletedRequest>) {
        for a in self.active.iter_mut() {
            if *a == Some(slot) {
                *a = None;
            }
        }
        let mut batches = Vec::new();
        let mut keep = Vec::new();
        for r in self.inflight.drain(..) {
            if r.ctx_slot == slot {
                batches.push(r);
            } else {
                keep.push(r);
            }
        }
        self.inflight = keep;
        if let Some(Some(ctx)) = self.contexts.get_mut(slot as usize) {
            let saved_head = ctx
                .image
                .read32(REG_STATE_PAGE_BYTE + ((CTX_RING_HEAD + 1) as u64) * 4);
            ctx.ring.head = saved_head & (RING_BYTES - 1);
            for r in &batches {
                ctx.last_completed_seqno = r.seqno;
            }
        }
        for r in batches {
            done.push(CompletedRequest {
                ctx: ContextId::pack(r.ctx_slot, r.ctx_gen),
                seqno: r.seqno,
                request: r.id,
            });
            self.alloc.free(r.batch.backing);
        }
    }

    /// Poll until the context's breadcrumb reaches `seqno` (in
    /// wrap-aware order) or the budget expires. Drives
    /// [`Self::poll_completions`] while waiting, like the other
    /// bounded register polls in this driver.
    pub fn wait_seqno(
        &mut self,
        id: ContextId,
        seqno: u32,
        timeout_ns: u64,
    ) -> Result<(), SubmitError> {
        let budget = narf_time::wall::ns_to_cycles(timeout_ns);
        let start = narf_time::now_cycles();
        loop {
            let _ = self.poll_completions();
            let last = self.last_completed_seqno(id)?;
            if seqno != 0 && (last.wrapping_sub(seqno) as i32) >= 0 && last != 0 {
                return Ok(());
            }
            if narf_time::now_cycles().wrapping_sub(start) > budget {
                return Err(SubmitError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
}

// ── Production glue ─────────────────────────────────────────────
//
// The engine attaches lazily to the probed controller in
// `intel_gpu` (Gen12 only) and submits on a default context.
// This is the driver-core entry point until a DRM execbuffer
// ABI exists above it; nothing else in the tree calls it yet.

/// `MmioWindow` over the controller's BAR0 mapping.
pub struct BarWindow {
    bar: narf_bus::bar::MmioRegion,
}

impl BarWindow {
    /// Wrap a BAR0 (`GTTMMADR`) mapping as an engine MMIO
    /// window. Shared by the RCS glue above and the media
    /// engines' glue in [`crate::intel_gpu_media`], which drive
    /// the same BAR0 at media-engine offsets.
    pub fn new(bar: narf_bus::bar::MmioRegion) -> Self {
        Self { bar }
    }
}

impl core::fmt::Debug for BarWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BarWindow")
            .field("phys", &self.bar.phys.raw())
            .finish()
    }
}

impl MmioWindow for BarWindow {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: `self.bar` is the BAR0 (`GTTMMADR`) region
        // mapped at probe; `off` is an engine register offset
        // inside the GT block, and a 32-bit register read has no
        // unwanted side effect.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.bar.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: same BAR ownership as `read32`; `off` is a
        // programmable engine register (ELSP / HWS_PGA).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.bar.write32(off, val) }
    }
}

type ProductionEngine = RcsEngine<BarWindow, SharedArena>;

static PRODUCTION_ARENA: narf_lib::sync::IrqSafeSpinLock<Option<SharedArena>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// The one GGTT arena every production engine on the probed
/// controller allocates from (RCS here, the media engines in
/// [`crate::intel_gpu_media`]). Created over the first probed
/// controller's BAR — the driver binds a single controller,
/// so first-wins matches the `CONTROLLER` singleton
/// discipline in `intel_gpu`.
pub fn production_arena(bar: narf_bus::bar::MmioRegion) -> SharedArena {
    let mut guard = PRODUCTION_ARENA.lock();
    if guard.is_none() {
        *guard = Some(SharedArena::new(GgttArena::new(bar)));
    }
    guard.as_ref().expect("set above").clone()
}

/// The default engine's production state: the engine
/// itself, its lazily created default context, the
/// forcewake manager submissions run under, and the
/// forcewake register window (a second `BarWindow` over the
/// same BAR0 the engine's window maps).
type RcsState = Option<(ProductionEngine, Option<ContextId>, Forcewake, BarWindow)>;

static RCS_STATE: narf_lib::sync::IrqSafeSpinLock<RcsState> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Power-management submission gate (Q9, #1015). While closed,
/// [`submit_dwords`] refuses with [`SubmitError::Suspended`]
/// before it can attach the engine or program a register, so
/// a suspending device never takes new work. The PM suspend
/// path closes the gate, drains completions until
/// [`production_idle`] holds, and only then touches power
/// state — which is also what makes the drain meaningful:
/// forcewake holds are scoped to a single submission, so a
/// closed gate plus a drained engine means zero holds exist.
static SUBMISSIONS_GATED: narf_lib::sync::IrqSafeSpinLock<bool> =
    narf_lib::sync::IrqSafeSpinLock::new(false);

/// Close or open the PM submission gate. Idempotent.
pub fn set_submission_gate(closed: bool) {
    *SUBMISSIONS_GATED.lock() = closed;
}

/// Whether the PM submission gate is currently closed.
pub fn submissions_gated() -> bool {
    *SUBMISSIONS_GATED.lock()
}

/// Whether the production engine has no work in flight. An
/// unattached engine is idle by definition (nothing was ever
/// submitted). Callers drain with
/// [`poll_default_completions`] until this holds.
pub fn production_idle() -> bool {
    let mut guard = RCS_STATE.lock();
    match guard.as_mut() {
        Some((engine, _, _, _)) => engine.is_idle(),
        None => true,
    }
}

fn attach_default() -> Result<(), SubmitError> {
    let (engine, fw_window) = crate::intel_gpu::with_controller(|gpu| {
        if !matches!(
            gpu.chip_info().generation,
            crate::intel_gpu::Generation::TigerLake | crate::intel_gpu::Generation::AlderLake
        ) {
            return None;
        }
        let arena = production_arena(gpu.gtt_mmadr);
        let engine = RcsEngine::new(BarWindow::new(gpu.gtt_mmadr), arena).ok()?;
        Some((engine, BarWindow::new(gpu.gtt_mmadr)))
    })
    .flatten()
    .ok_or(SubmitError::NoEngine)?;
    // Mirror i915's probe-time fw_domain_reset: clear any
    // forcewake request state firmware left behind before the
    // first submission takes a hold.
    let mut fw = Forcewake::new();
    fw.sanitize(&fw_window);
    *RCS_STATE.lock() = Some((engine, None, fw, fw_window));
    Ok(())
}

/// Submit raw batch dwords on the default context of the
/// probed Gen12 controller, attaching the RCS0 engine on first
/// use. Returns the engine-wide request id; completion is
/// observed through [`poll_default_completions`].
pub fn submit_dwords(dwords: &[u32]) -> Result<u64, SubmitError> {
    // PM gate first: a gated submission must not attach the
    // engine or touch hardware on its way to refusal.
    if submissions_gated() {
        return Err(SubmitError::Suspended);
    }
    let mut guard = RCS_STATE.lock();
    if guard.is_none() {
        drop(guard);
        attach_default()?;
        guard = RCS_STATE.lock();
    }
    let (engine, default_ctx, fw, fw_window) = guard.as_mut().expect("attached above");
    // The submission conversation programs RCS0 registers
    // (ELSP, ring registers) — render-domain registers gated
    // on forcewake. Take the hold for exactly the
    // conversation; an acquire failure means nothing was
    // programmed.
    fw.acquire(fw_window, FwDomain::Render)
        .map_err(|_| SubmitError::Forcewake)?;
    let result: Result<u64, SubmitError> = (|| {
        if default_ctx.is_none() {
            *default_ctx = Some(engine.create_context()?);
        }
        let ctx = default_ctx.expect("created above");
        let batch = engine.write_batch(dwords)?;
        engine.submit(ctx, batch)
    })();
    // A release failure (ack slow to clear) still drops the
    // hold in state and leaves the hardware awake — the safe
    // direction — so the submission's own result stands.
    let _ = fw.release(fw_window, FwDomain::Render);
    result
}

/// Drain completions from the default engine, if attached.
/// Takes no forcewake hold: completions are read from the
/// CSB in the status page, which is host memory (a
/// `GpuBacking`), not a gated register.
pub fn poll_default_completions() -> Vec<CompletedRequest> {
    let mut guard = RCS_STATE.lock();
    match guard.as_mut() {
        Some((engine, _, _, _)) => engine.poll_completions(),
        None => Vec::new(),
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the submission path. The fake hardware is a
    //! *model of the GPU*, not of the driver: it watches the
    //! ELSP write stream, and on each submission burst it loads
    //! the named context's image, executes its ring (following
    //! `MI_BATCH_BUFFER_START` into the batch, performing
    //! `MI_STORE_DWORD_IMM` breadcrumbs), saves the head back
    //! into the image, and posts Gen12 CSB entries into the
    //! engine status page — the same conversation real silicon
    //! would have, so the driver code under test cannot tell
    //! the difference.

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Fake MMIO ───────────────────────────────────────────

    #[derive(Clone)]
    struct FakeRegs {
        map: Rc<RefCell<BTreeMap<u64, u32>>>,
        writes: Rc<RefCell<Vec<(u64, u32)>>>,
    }

    impl FakeRegs {
        fn new() -> Self {
            Self {
                map: Rc::new(RefCell::new(BTreeMap::new())),
                writes: Rc::new(RefCell::new(Vec::new())),
            }
        }
        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for FakeRegs {
        fn read32(&self, off: u64) -> u32 {
            *self.map.borrow().get(&off).unwrap_or(&0)
        }
        fn write32(&self, off: u64, val: u32) {
            self.map.borrow_mut().insert(off, val);
            self.writes.borrow_mut().push((off, val));
        }
    }

    // ── Fake backing + arena ────────────────────────────────

    struct FakeBacking {
        ggtt: u32,
        pages: u32,
        mem: Rc<RefCell<Vec<u8>>>,
    }

    fn mem_rd(mem: &Rc<RefCell<Vec<u8>>>, off: u64) -> u32 {
        let m = mem.borrow();
        u32::from_le_bytes([
            m[off as usize],
            m[off as usize + 1],
            m[off as usize + 2],
            m[off as usize + 3],
        ])
    }

    fn mem_wr(mem: &Rc<RefCell<Vec<u8>>>, off: u64, val: u32) {
        let mut m = mem.borrow_mut();
        m[off as usize..off as usize + 4].copy_from_slice(&val.to_le_bytes());
    }

    impl GpuBacking for FakeBacking {
        fn ggtt_offset(&self) -> u32 {
            self.ggtt
        }
        fn size_pages(&self) -> u32 {
            self.pages
        }
        fn read32(&self, byte_off: u64) -> u32 {
            mem_rd(&self.mem, byte_off)
        }
        fn write32(&self, byte_off: u64, val: u32) {
            mem_wr(&self.mem, byte_off, val)
        }
    }

    /// Shared fake GGTT object store (GGTT offset -> backing
    /// bytes), shared between the fake arena and the fake
    /// hardware so both observe the same objects.
    type FakeObjectRegistry = Rc<RefCell<BTreeMap<u32, Rc<RefCell<Vec<u8>>>>>>;

    struct FakeArena {
        free_list: Vec<(u32, u32)>,
        next: u32,
        live: usize,
        live_pages: u32,
        registry: FakeObjectRegistry,
    }

    impl FakeArena {
        fn new(registry: FakeObjectRegistry) -> Self {
            Self {
                free_list: Vec::new(),
                next: GGTT_ARENA_BASE,
                live: 0,
                live_pages: 0,
                registry,
            }
        }
    }

    impl GpuAllocator for FakeArena {
        type Backing = FakeBacking;

        fn alloc(&mut self, pages: u32) -> Result<FakeBacking, SubmitError> {
            let ggtt = match self.free_list.iter().position(|&(_, len)| len >= pages) {
                Some(i) => {
                    let (off, len) = self.free_list.remove(i);
                    if len > pages {
                        self.free_list.push((off + pages * 4096, len - pages));
                    }
                    off
                }
                None => {
                    let off = self.next;
                    self.next += pages * 4096;
                    if self.next > GGTT_ARENA_BASE + GGTT_ARENA_PAGES * 4096 {
                        return Err(SubmitError::OutOfMemory);
                    }
                    off
                }
            };
            let mem = Rc::new(RefCell::new(alloc::vec![0u8; (pages * 4096) as usize]));
            self.registry.borrow_mut().insert(ggtt, mem.clone());
            self.live += 1;
            self.live_pages += pages;
            Ok(FakeBacking { ggtt, pages, mem })
        }

        fn free(&mut self, backing: FakeBacking) {
            self.registry.borrow_mut().remove(&backing.ggtt);
            self.free_list.push((backing.ggtt, backing.pages));
            self.live -= 1;
            self.live_pages -= backing.pages;
        }

        fn live_allocations(&self) -> usize {
            self.live
        }
        fn live_pages(&self) -> u32 {
            self.live_pages
        }
    }

    // ── Fake hardware ───────────────────────────────────────

    fn csb_promote(to: u16) -> CsbEntry {
        CsbEntry {
            lower: (to as u32) << 15,
            upper: (IDLE_SW_ID as u32) << 15,
        }
    }

    fn csb_complete(away: u16, to: u16) -> CsbEntry {
        CsbEntry {
            lower: (to as u32) << 15,
            upper: (away as u32) << 15,
        }
    }

    fn csb_preempt(away: u16, to: u16) -> CsbEntry {
        CsbEntry {
            lower: 1 | ((to as u32) << 15),
            upper: (away as u32) << 15,
        }
    }

    struct FakeHw {
        regs: FakeRegs,
        registry: FakeObjectRegistry,
        status_ggtt: u32,
        write_ptr: u8,
        consumed_elsp: usize,
    }

    impl FakeHw {
        fn new(regs: FakeRegs, registry: FakeObjectRegistry, status_ggtt: u32) -> Self {
            Self {
                regs,
                registry,
                status_ggtt,
                write_ptr: 0,
                consumed_elsp: 0,
            }
        }

        fn mem(&self, ggtt: u32) -> Rc<RefCell<Vec<u8>>> {
            self.registry
                .borrow()
                .get(&ggtt)
                .expect("fake hw: unknown GGTT object")
                .clone()
        }

        /// Run every ELSP burst the driver has rung since the
        /// last step: promote the first context, execute each
        /// context's ring in port order, and post the CSB
        /// stream real hardware would produce.
        fn step(&mut self) {
            let elsp: Vec<u32> = self
                .regs
                .writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == RING_ELSP)
                .map(|(_, v)| *v)
                .collect();
            while self.consumed_elsp + 4 <= elsp.len() {
                let g = &elsp[self.consumed_elsp..self.consumed_elsp + 4];
                self.consumed_elsp += 4;
                let port1 = ((g[0] as u64) << 32) | g[1] as u64;
                let port0 = ((g[2] as u64) << 32) | g[3] as u64;
                if port0 == 0 {
                    continue;
                }
                self.push_csb(csb_promote(descriptor_sw_id(port0)));
                self.execute(port0);
                if port1 != 0 {
                    self.push_csb(csb_complete(
                        descriptor_sw_id(port0),
                        descriptor_sw_id(port1),
                    ));
                    self.execute(port1);
                    self.push_csb(csb_complete(descriptor_sw_id(port1), IDLE_SW_ID));
                } else {
                    self.push_csb(csb_complete(descriptor_sw_id(port0), IDLE_SW_ID));
                }
            }
        }

        /// Execute one loaded context: run its ring from the
        /// image head to the image tail, then save head = tail
        /// back into the image.
        fn execute(&mut self, desc: u64) {
            let image = self.mem(descriptor_lrca(desc));
            let rs = REG_STATE_PAGE_BYTE;
            let ring_start = mem_rd(&image, rs + ((CTX_RING_BUFFER_START + 1) as u64) * 4);
            let head = mem_rd(&image, rs + ((CTX_RING_HEAD + 1) as u64) * 4);
            let tail = mem_rd(&image, rs + ((CTX_RING_TAIL + 1) as u64) * 4);
            let ring = self.mem(ring_start);
            let mask = RING_BYTES - 1;
            let mut pos = head & mask;
            let tail = tail & mask;
            let mut guard = 0u32;
            while pos != tail && guard < RING_BYTES {
                guard += 4;
                let dw = mem_rd(&ring, pos as u64);
                match dw >> 23 {
                    0x31 => {
                        let lo = mem_rd(&ring, ((pos + 4) & mask) as u64) as u64;
                        let hi = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                        self.execute_batch((lo | (hi << 32)) as u32);
                        pos = (pos + 12) & mask;
                    }
                    0x20 => {
                        let lo = mem_rd(&ring, ((pos + 4) & mask) as u64) as u64;
                        let hi = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                        let data = mem_rd(&ring, ((pos + 12) & mask) as u64);
                        self.write_ggtt(lo | (hi << 32), data);
                        pos = (pos + 16) & mask;
                    }
                    _ => pos = (pos + 4) & mask,
                }
            }
            mem_wr(&image, rs + ((CTX_RING_HEAD + 1) as u64) * 4, tail);
        }

        fn execute_batch(&mut self, ggtt: u32) {
            let batch = self.mem(ggtt);
            let len = batch.borrow().len() as u64;
            let mut pos = 0u64;
            while pos + 4 <= len {
                let dw = mem_rd(&batch, pos);
                match dw >> 23 {
                    0x0A => break,
                    0x20 => {
                        let lo = mem_rd(&batch, pos + 4) as u64;
                        let hi = mem_rd(&batch, pos + 8) as u64;
                        let data = mem_rd(&batch, pos + 12);
                        self.write_ggtt(lo | (hi << 32), data);
                        pos += 16;
                    }
                    _ => pos += 4,
                }
            }
        }

        /// Perform a GPU-side dword write to a GGTT address,
        /// resolving it against the arena registry.
        fn write_ggtt(&self, addr: u64, data: u32) {
            let reg = self.registry.borrow();
            for (base, mem) in reg.iter() {
                let size = mem.borrow().len() as u64;
                if addr >= *base as u64 && addr + 4 <= *base as u64 + size {
                    mem_wr(mem, addr - *base as u64, data);
                    return;
                }
            }
            panic!("fake hw: store to unmapped GGTT address");
        }

        fn push_csb(&mut self, entry: CsbEntry) {
            self.write_ptr = (self.write_ptr + 1) % CSB_ENTRIES;
            let status = self.mem(self.status_ggtt);
            let off = CSB_BUF_BYTE + (self.write_ptr as u64) * 8;
            mem_wr(&status, off, entry.lower);
            mem_wr(&status, off + 4, entry.upper);
            mem_wr(&status, CSB_WRITE_BYTE, self.write_ptr as u32);
        }

        /// Post a CSB entry outside the normal execution flow
        /// (preemption / spurious-event fixtures).
        fn inject_csb(&mut self, entry: CsbEntry) {
            self.push_csb(entry);
        }
    }

    fn make_engine() -> Result<(RcsEngine<FakeRegs, FakeArena>, FakeHw), TestResult> {
        let regs = FakeRegs::new();
        let registry = Rc::new(RefCell::new(BTreeMap::new()));
        let arena = FakeArena::new(registry.clone());
        let engine = match RcsEngine::new(regs.clone(), arena) {
            Ok(e) => e,
            Err(_) => return Err(TestResult::Fail("engine init")),
        };
        let hw = FakeHw::new(regs, registry, engine.status_ggtt());
        Ok((engine, hw))
    }

    // ── Codec fixtures ──────────────────────────────────────

    fn smoke_descriptor_layout() -> TestResult {
        let desc = context_descriptor(0x1000_0000, 5);
        if desc & DESC_VALID == 0 {
            return TestResult::Fail("VALID bit clear");
        }
        if desc & DESC_MODE_LEGACY_64B != DESC_MODE_LEGACY_64B {
            return TestResult::Fail("mode is not Legacy-64B");
        }
        if desc & (DESC_L3LLC_COHERENT | DESC_PRIVILEGE) != DESC_L3LLC_COHERENT | DESC_PRIVILEGE {
            return TestResult::Fail("coherent/privilege flags lost");
        }
        if descriptor_lrca(desc) != 0x1000_0000 {
            return TestResult::Fail("LRCA round-trip");
        }
        if descriptor_sw_id(desc) != 5 {
            return TestResult::Fail("SW id round-trip");
        }
        // Upper dword: only the SW id field (bits 37:47) may be
        // set — engine class/instance/counter stay zero.
        if (desc >> 32) & !0xFFE0 != 0 {
            return TestResult::Fail("unexpected upper-dword bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_descriptor_layout);

    fn smoke_mi_encodings() -> TestResult {
        let bb = mi_batch_buffer_start_ggtt(0x1_2345_6000);
        if bb != [0x1880_0001, 0x2345_6000, 0x1] {
            return TestResult::Fail("MI_BATCH_BUFFER_START encoding");
        }
        if bb[0] & BB_START_ASI_PPGTT != 0 {
            return TestResult::Fail("batch must address via GGTT");
        }
        let sd = mi_store_dword_imm_ggtt(0x1000_0040, 0xDEAD_BEEF);
        if sd != [0x1040_0002, 0x1000_0040, 0x0, 0xDEAD_BEEF] {
            return TestResult::Fail("MI_STORE_DWORD_IMM encoding");
        }
        if mi_load_register_imm(14, true) != 0x1100_101B {
            return TestResult::Fail("LRI header for 14 posted pairs");
        }
        if mi_load_register_imm(9, true) != 0x1100_1011 {
            return TestResult::Fail("LRI header for 9 posted pairs");
        }
        if mi_load_register_imm(1, false) != 0x1100_0001 {
            return TestResult::Fail("LRI header for 1 pair");
        }
        if ring_ctl_value(RING_BYTES) != 0x1_f001 {
            return TestResult::Fail("RING_CTL for a 128 KiB ring");
        }
        if CTX_CONTROL_VALUE != 0x0009_0008 {
            return TestResult::Fail("CONTEXT_CONTROL template value");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_mi_encodings);

    fn smoke_reg_state_template() -> TestResult {
        let r = build_reg_state(0x1004_0000, RING_BYTES);
        if CSB_ENTRIES != 12 || REG_STATE_DWORDS != 186 {
            return TestResult::Fail("Gen12 CSB depth or context restore length");
        }
        if r[0] != MI_NOOP || r[CTX_LRI_HEADER_0] != 0x1108_1019 {
            return TestResult::Fail("group 0 header");
        }
        if r[CTX_CONTEXT_CONTROL] != RING_CONTEXT_CONTROL as u32
            || r[CTX_CONTEXT_CONTROL + 1] != CTX_CONTROL_VALUE
        {
            return TestResult::Fail("context control pair");
        }
        if r[CTX_RING_TAIL] != RING_TAIL as u32 || r[CTX_RING_TAIL + 1] != 0 {
            return TestResult::Fail("ring tail pair");
        }
        if r[CTX_RING_BUFFER_START] != RING_START as u32
            || r[CTX_RING_BUFFER_START + 1] != 0x1004_0000
        {
            return TestResult::Fail("ring start pair");
        }
        if r[CTX_RING_BUFFER_CONTROL + 1] != 0x1_f001 {
            return TestResult::Fail("ring ctl value");
        }
        if r[CTX_LRI_HEADER_1] != 0x1108_1011 {
            return TestResult::Fail("group 1 header");
        }
        // PDP pairs name descending PDPs and carry zero values.
        // Each PDP spans two pairs — UDW then LDW — so successive
        // PDPs sit 4 dwords apart: PDP3 at CTX_PDP3_UDW, PDP2 at
        // +4, PDP1 at +8, PDP0 at +12.
        if r[CTX_PDP3_UDW] != ring_pdp_udw(3) as u32 || r[CTX_PDP3_UDW + 1] != 0 {
            return TestResult::Fail("PDP3 pair");
        }
        if r[CTX_PDP3_UDW + 2] != ring_pdp_ldw(3) as u32 || r[CTX_PDP3_UDW + 3] != 0 {
            return TestResult::Fail("PDP3 LDW pair");
        }
        if r[CTX_PDP3_UDW + 4] != ring_pdp_udw(2) as u32 {
            return TestResult::Fail("PDP2 pair position");
        }
        if r[CTX_PDP3_UDW + 8] != ring_pdp_udw(1) as u32 {
            return TestResult::Fail("PDP1 pair position");
        }
        if r[CTX_PDP3_UDW + 12] != ring_pdp_udw(0) as u32 {
            return TestResult::Fail("PDP0 pair position");
        }
        if r[CTX_LRI_HEADER_2] != 0x1108_0001 || r[CTX_R_PWR_CLK_STATE] != R_PWR_CLK_STATE as u32 {
            return TestResult::Fail("group 2 (RCS power clock state)");
        }
        if r[CTX_END] != MI_BATCH_BUFFER_END | 1 {
            return TestResult::Fail("template terminator");
        }
        if r[0x34] != 0x1108_1005
            || r[0x35] != 0x21b0
            || r[0x37] != 0x25a8
            || r[0x39] != 0x25ac
            || r[0x51] != 0x1108_1065
            || r[0x52] != 0x2588
            || r[0x5e] != 0x2028
            || r[0xb6] != 0x2084
            || r[0xb8] != 0
        {
            return TestResult::Fail("Gen12 extended context restore groups");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_reg_state_template);

    fn smoke_csb_parse() -> TestResult {
        if csb_step(&csb_promote(3), false) != CsbStep::Promote {
            return TestResult::Fail("promote parse");
        }
        if csb_step(&csb_complete(3, IDLE_SW_ID), true) != CsbStep::Complete {
            return TestResult::Fail("complete parse");
        }
        if csb_step(&csb_complete(3, 4), true) != CsbStep::Complete {
            return TestResult::Fail("complete-with-successor parse");
        }
        if csb_step(&csb_preempt(3, 4), true) != CsbStep::Preempt {
            return TestResult::Fail("preempt parse");
        }
        // A completion with nothing active is not a completion.
        if csb_step(&csb_complete(3, IDLE_SW_ID), false) != CsbStep::Nop {
            return TestResult::Fail("idle complete must be Nop");
        }
        // A wait-on-semaphore detail is recorded, not acted on.
        let wait = CsbEntry {
            lower: (3u32) << 15,
            upper: ((3u32) << 15) | 4,
        };
        if csb_step(&wait, true) != CsbStep::Nop {
            return TestResult::Fail("wait detail must be Nop");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_csb_parse);

    fn smoke_ring_wrap_and_full() -> TestResult {
        let mem = FakeBacking {
            ggtt: 0,
            pages: RING_PAGES,
            mem: Rc::new(RefCell::new(alloc::vec![0u8; RING_BYTES as usize])),
        };
        // Start 16 bytes before the wrap with an empty ring.
        let mut ring = RingState {
            head: RING_BYTES - 16,
            tail: RING_BYTES - 16,
        };
        let prog: [u32; 7] = [0x1880_0001, 0x10, 0x0, 0x1040_0002, 0x20, 0x0, 0x7];
        if ring_emit(&mem, &mut ring, &prog).is_err() {
            return TestResult::Fail("wrap emit rejected");
        }
        // Padding dwords are MI_NOOP; the program landed at 0.
        for i in 0..4u64 {
            if mem.read32(RING_BYTES as u64 - 16 + i * 4) != MI_NOOP {
                return TestResult::Fail("wrap padding is not MI_NOOP");
            }
        }
        for (i, dw) in prog.iter().enumerate() {
            if mem.read32((i as u64) * 4) != *dw {
                return TestResult::Fail("wrapped program misplaced");
            }
        }
        if ring.tail != 28 {
            return TestResult::Fail("tail after wrap");
        }
        // A command larger than the ring's usable span is full.
        let mut empty = RingState { head: 0, tail: 0 };
        let huge = alloc::vec![0u32; (RING_BYTES / 4) as usize];
        if ring_emit(&mem, &mut empty, &huge) != Err(SubmitError::RingFull) {
            return TestResult::Fail("oversize emit must be RingFull");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_ring_wrap_and_full);

    // ── End-to-end fixtures ─────────────────────────────────

    fn smoke_submit_end_to_end() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        // Engine init programmed HWS_PGA with the status page.
        if hw.regs.writes_to(RING_HWS_PGA) != [engine.status_ggtt()] {
            return TestResult::Fail("HWS_PGA not programmed");
        }
        let ctx = match engine.create_context() {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("create context"),
        };
        // status page + image + ring + ctx status page.
        if engine.live_allocations() != 4 {
            return TestResult::Fail("allocation accounting after create");
        }
        let batch = match engine.write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("write batch"),
        };
        if engine.submit(ctx, batch).is_err() {
            return TestResult::Fail("submit");
        }
        // ELSP burst: port 1 zero descriptor first, then the
        // port-0 descriptor (high, low) as the doorbell.
        let elsp = hw.regs.writes_to(RING_ELSP);
        if elsp.len() != 4 || elsp[0] != 0 || elsp[1] != 0 {
            return TestResult::Fail("ELSP write order");
        }
        let desc = ((elsp[2] as u64) << 32) | elsp[3] as u64;
        if descriptor_sw_id(desc) != 1 || descriptor_lrca(desc) == 0 {
            return TestResult::Fail("ELSP descriptor contents");
        }
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != ctx || done[0].seqno != 1 {
            return TestResult::Fail("completion stream");
        }
        // The breadcrumb landed in the context status page and
        // the batch allocation was retired with the request.
        if engine.hw_seqno(ctx) != Ok(1) {
            return TestResult::Fail("breadcrumb seqno");
        }
        if engine.live_allocations() != 4 {
            return TestResult::Fail("batch not freed at retirement");
        }
        if engine.wait_seqno(ctx, 1, 1_000_000).is_err() {
            return TestResult::Fail("wait_seqno on completed seqno");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_submit_end_to_end);

    fn smoke_two_contexts_pipeline() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let c1 = engine.create_context().expect("ctx1");
        let c2 = engine.create_context().expect("ctx2");
        let b1 = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch1");
        let b2 = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch2");
        engine.submit(c1, b1).expect("submit1");
        // The first submit already rang the doorbell with an
        // empty port 1; the second context queues behind it.
        engine.submit(c2, b2).expect("submit2");
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != c1 {
            return TestResult::Fail("first completion should be ctx1 only");
        }
        // Draining pumped ctx2 into the ports.
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != c2 {
            return TestResult::Fail("second completion should be ctx2");
        }
        if engine.hw_seqno(c1) != Ok(1) || engine.hw_seqno(c2) != Ok(1) {
            return TestResult::Fail("per-context breadcrumbs");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_two_contexts_pipeline);

    fn smoke_busy_destroy_accounting() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctx = engine.create_context().expect("ctx");
        let batch = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch");
        engine.submit(ctx, batch).expect("submit");
        // While the context sits in the pending ports, a second
        // submit and a destroy are both refused — and the
        // refused submit's batch is reclaimed, not leaked.
        let before = engine.live_allocations();
        let batch2 = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch2");
        if engine.submit(ctx, batch2) != Err(SubmitError::ContextBusy) {
            return TestResult::Fail("submit on loaded context must be ContextBusy");
        }
        if engine.live_allocations() != before {
            return TestResult::Fail("refused submit leaked its batch");
        }
        if engine.destroy_context(ctx) != Err(SubmitError::ContextBusy) {
            return TestResult::Fail("destroy of loaded context must be ContextBusy");
        }
        hw.step();
        let _ = engine.poll_completions();
        if engine.destroy_context(ctx).is_err() {
            return TestResult::Fail("destroy after drain");
        }
        // Only the engine status page remains.
        if engine.live_allocations() != 1 {
            return TestResult::Fail("destroy did not reclaim all allocations");
        }
        // The stale handle names a dead generation now.
        let batch3 = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch3");
        if engine.submit(ctx, batch3) != Err(SubmitError::UnknownContext) {
            return TestResult::Fail("stale handle must be UnknownContext");
        }
        if engine.destroy_context(ctx) != Err(SubmitError::UnknownContext) {
            return TestResult::Fail("double destroy must be UnknownContext");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_busy_destroy_accounting);

    fn smoke_queued_third_context() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctxs = [
            engine.create_context().expect("ctx1"),
            engine.create_context().expect("ctx2"),
            engine.create_context().expect("ctx3"),
        ];
        for c in ctxs {
            let b = engine
                .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
                .expect("batch");
            engine.submit(c, b).expect("submit");
        }
        // The first submit rang the doorbell alone; the other
        // two queue behind it. Each drain pumps the next burst:
        // completions arrive 1 (first burst), then 2 (the
        // paired burst the pump assembled), then none.
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 {
            return TestResult::Fail("expected exactly one completion per burst");
        }
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 2 {
            return TestResult::Fail("expected the paired burst to retire both contexts");
        }
        hw.step();
        let done = engine.poll_completions();
        if !done.is_empty() {
            return TestResult::Fail("no work should remain");
        }
        for c in ctxs {
            if engine.hw_seqno(c) != Ok(1) {
                return TestResult::Fail("every context ran exactly once");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_queued_third_context);

    fn smoke_queue_full() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let c1 = engine.create_context().expect("c1");
        let c2 = engine.create_context().expect("c2");
        let c3 = engine.create_context().expect("c3");
        // Ring the doorbell for ctx1; ctx2's request queues
        // behind the occupied ports (no hardware step yet, so
        // nothing drains).
        for c in [c1, c2] {
            let b = engine
                .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
                .expect("batch");
            engine.submit(c, b).expect("port submit");
        }
        // Fill the queue with requests for the third context.
        // (One queue slot is already taken by ctx2's request.)
        for _ in 0..MAX_QUEUED_REQUESTS - 1 {
            let b = engine
                .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
                .expect("batch");
            if engine.submit(c3, b).is_err() {
                return TestResult::Fail("queue filled early");
            }
        }
        let b = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch");
        if engine.submit(c3, b) != Err(SubmitError::QueueFull) {
            return TestResult::Fail("queue capacity not enforced");
        }
        // Drain everything; every queued breadcrumb must land.
        for _ in 0..4 {
            hw.step();
            let _ = engine.poll_completions();
        }
        if engine.hw_seqno(c3) != Ok((MAX_QUEUED_REQUESTS - 1) as u32) {
            return TestResult::Fail("queued requests did not all retire");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_queue_full);

    fn smoke_preempt_requeue() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctx = engine.create_context().expect("ctx");
        let batch = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch");
        engine.submit(ctx, batch).expect("submit");
        let elsp_before = hw.regs.writes_to(RING_ELSP).len();
        // Hardware promotes, then preempts to an empty queue
        // before the batch runs.
        hw.inject_csb(csb_promote(1));
        hw.inject_csb(csb_preempt(1, IDLE_SW_ID));
        let done = engine.poll_completions();
        if !done.is_empty() {
            return TestResult::Fail("preempted work must not retire");
        }
        // The drain re-pumped the context into the ELSP.
        if hw.regs.writes_to(RING_ELSP).len() <= elsp_before {
            return TestResult::Fail("preempted context was not resubmitted");
        }
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].seqno != 1 {
            return TestResult::Fail("resubmitted context did not complete");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_preempt_requeue);

    fn smoke_batch_validation() -> TestResult {
        let (mut engine, _) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        if engine.write_batch(&[]).is_ok() {
            return TestResult::Fail("empty batch accepted");
        }
        if engine.write_batch(&[MI_NOOP]).is_ok() {
            return TestResult::Fail("batch without MI_BATCH_BUFFER_END accepted");
        }
        if engine.write_batch(&[MI_BATCH_BUFFER_END]).is_err() {
            return TestResult::Fail("minimal batch rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_batch_validation);

    fn smoke_unknown_context() -> TestResult {
        let (mut engine, _) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let bogus = ContextId::pack(9, 1);
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).expect("batch");
        if engine.submit(bogus, batch) != Err(SubmitError::UnknownContext) {
            return TestResult::Fail("submit to unknown context");
        }
        if engine.destroy_context(bogus) != Err(SubmitError::UnknownContext) {
            return TestResult::Fail("destroy of unknown context");
        }
        if !engine.poll_completions().is_empty() {
            return TestResult::Fail("fresh engine produced completions");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_unknown_context);

    fn smoke_wait_seqno_timeout() -> TestResult {
        let (mut engine, _) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctx = engine.create_context().expect("ctx");
        let batch = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch");
        engine.submit(ctx, batch).expect("submit");
        // The hardware never steps, so the wait must expire.
        if engine.wait_seqno(ctx, 1, 1_000) != Err(SubmitError::Timeout) {
            return TestResult::Fail("wait_seqno must time out without hardware progress");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_wait_seqno_timeout);

    fn smoke_spurious_csb() -> TestResult {
        let (mut engine, mut hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        // A completion naming a context that does not exist is
        // counted and otherwise ignored — it must not retire or
        // fabricate work. The real context is promoted first so
        // the completion branch is genuinely reachable (a
        // completion with nothing active parses as Nop).
        let ctx = engine.create_context().expect("ctx");
        let batch = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch");
        engine.submit(ctx, batch).expect("submit");
        hw.inject_csb(csb_promote(1));
        let _ = engine.poll_completions();
        hw.inject_csb(csb_complete(40, IDLE_SW_ID));
        let done = engine.poll_completions();
        if !done.is_empty() {
            return TestResult::Fail("spurious completion retired work");
        }
        if engine.spurious_csb() != 1 {
            return TestResult::Fail("spurious completion not counted");
        }
        // The real context still completes normally afterwards.
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != ctx {
            return TestResult::Fail("real completion lost after spurious entry");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_spurious_csb);

    fn smoke_ppgtt_batch_start_encoding() -> TestResult {
        // The PPGTT form differs from the GGTT form by exactly
        // the ASI bit; both carry a 64-bit address in dwords
        // 1..2. Hand-computed header: (0x31 << 23) | 1 | (1 << 8)
        // = 0x1880_0101.
        let enc = mi_batch_buffer_start_ppgtt(0x0000_0001_2345_6000);
        if enc != [0x1880_0101, 0x2345_6000, 0x0000_0001] {
            return TestResult::Fail("PPGTT batch-start encoding wrong");
        }
        let ggtt = mi_batch_buffer_start_ggtt(0x0000_0001_2345_6000);
        if enc[0] ^ ggtt[0] != BB_START_ASI_PPGTT {
            return TestResult::Fail("PPGTT/GGTT forms must differ only in the ASI bit");
        }
        if enc[1..] != ggtt[1..] {
            return TestResult::Fail("address dwords must match the GGTT form");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_ppgtt_batch_start_encoding
    );

    fn smoke_attach_ppgtt_programs_pdp0() -> TestResult {
        let (mut engine, hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctx = engine.create_context().expect("ctx");
        // The image lives in the fake GGTT registry under its
        // LRCA; read the register-state page through it.
        let lrca = {
            let c = engine.contexts[ctx.slot() as usize]
                .as_ref()
                .expect("live ctx");
            descriptor_lrca(c.descriptor)
        };
        let image = hw.mem(lrca);
        let pdp_val = |pair: u64, high: bool| {
            let idx = CTX_PDP3_UDW as u64 + pair * 4 + if high { 1 } else { 3 };
            mem_rd(&image, REG_STATE_PAGE_BYTE + idx * 4)
        };
        // Fresh context: every PDP value is zero (GGTT only).
        for pair in 0..4 {
            if pdp_val(pair, true) != 0 || pdp_val(pair, false) != 0 {
                return TestResult::Fail("fresh context must have zero PDPs");
            }
        }
        if engine.ppgtt_root(ctx) != Ok(None) {
            return TestResult::Fail("fresh context must report no PPGTT root");
        }
        // Invalid roots are refused before any patch.
        match engine.attach_ppgtt(ctx, 0x1234) {
            Err(SubmitError::InvalidPpgttRoot) => {}
            _ => return TestResult::Fail("unaligned root must be refused"),
        }
        match engine.attach_ppgtt(ctx, 1u64 << 46) {
            Err(SubmitError::InvalidPpgttRoot) => {}
            _ => return TestResult::Fail(">46-bit root must be refused"),
        }
        // Attach: PDP0 carries the raw PML4 root address
        // (raw phys = 0x4000_0000 here); PDP1-3 stay zero.
        engine.attach_ppgtt(ctx, 0x4000_0000).expect("attach");
        if engine.ppgtt_root(ctx) != Ok(Some(0x4000_0000)) {
            return TestResult::Fail("attached root not reported");
        }
        if pdp_val(3, false) != 0x4000_0000 || pdp_val(3, true) != 0 {
            return TestResult::Fail("PDP0 must carry raw root physical address");
        }
        for pair in 0..3 {
            if pdp_val(pair, true) != 0 || pdp_val(pair, false) != 0 {
                return TestResult::Fail("PDP1-3 must stay zero in 4-level mode");
            }
        }
        // A loaded context refuses re-attach: submit covers the
        // context (pending port), and the root must not change
        // under the hardware.
        let batch = engine
            .write_batch(&[MI_NOOP, MI_BATCH_BUFFER_END])
            .expect("batch");
        engine.submit(ctx, batch).expect("submit");
        match engine.attach_ppgtt(ctx, 0x5000_0000) {
            Err(SubmitError::ContextBusy) => {}
            _ => return TestResult::Fail("attach on a covered context must be ContextBusy"),
        }
        if engine.ppgtt_root(ctx) != Ok(Some(0x4000_0000)) {
            return TestResult::Fail("refused attach must not replace the root");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_attach_ppgtt_programs_pdp0
    );

    fn smoke_detach_ppgtt_zeroes_pdps() -> TestResult {
        let (mut engine, hw) = match make_engine() {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctx = engine.create_context().expect("ctx");
        engine.attach_ppgtt(ctx, 0x4000_0000).expect("attach");
        engine.detach_ppgtt(ctx).expect("detach");
        if engine.ppgtt_root(ctx) != Ok(None) {
            return TestResult::Fail("detached context must report no root");
        }
        let lrca = {
            let c = engine.contexts[ctx.slot() as usize]
                .as_ref()
                .expect("live ctx");
            descriptor_lrca(c.descriptor)
        };
        let image = hw.mem(lrca);
        for pair in 0..4u64 {
            for slot in [1u64, 3] {
                let idx = CTX_PDP3_UDW as u64 + pair * 4 + slot;
                if mem_rd(&image, REG_STATE_PAGE_BYTE + idx * 4) != 0 {
                    return TestResult::Fail("detach must zero every PDP value");
                }
            }
        }
        // Re-attach after detach works and lands the new root.
        engine.attach_ppgtt(ctx, 0x6000_0000).expect("re-attach");
        if engine.ppgtt_root(ctx) != Ok(Some(0x6000_0000)) {
            return TestResult::Fail("re-attached root not reported");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_detach_ppgtt_zeroes_pdps);
}
