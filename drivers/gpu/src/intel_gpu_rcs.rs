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
//!   (GGTT), cache drain/stall and a post-sync breadcrumb to the context's
//!   ring, advances the image tail, and — when an execlist port
//!   is free — writes the context descriptors to the ELSP in the
//!   hardware order (port 1 high/low, then port 0 high/low; the
//!   final write is the doorbell).
//! - **Completion.** The engine status page (programmed into
//!   `RING_HWS_PGA` at engine init) receives Gen12-format context
//!   status buffer (CSB) entries; `poll_completions` drains them
//!   (promote / preempt / complete), verifies breadcrumb/head, retires requests, frees
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
//! The CSB depth is twelve on Gen11+ (MIT intel_lrc_reg.h) and six
//! on Gen9 (`GEN8_CSB_ENTRIES`); see [`csb_entries`]. The 48-page
//! image allocation bounds the 14-page render image shared by Gen11
//! and Gen12 (`intel_engine_context_size`) and the 22-page Gen9
//! render image (`GEN9_LR_CONTEXT_RENDER_SIZE`); see
//! [`render_image_pages`]. The Gen11 template itself differs —
//! see [`build_reg_state_for_generation`].
//!
//! Gen9 and Gen11 follow Linux's execlists path rather than the Gen12
//! shape: their CSB entries are Gen8-format ([`gen8_csb_step`], each
//! consumed entry reset to all-ones as `csb_read` does), Gen11 loads its
//! ports through the execlist submit queue ([`uses_submit_queue`]), a
//! render request is the `gen8_engine_cs.c` invalidate / batch / flush /
//! breadcrumb stream, resident batches use the Gen8 PTE format, and ports
//! are only loaded into an idle engine, since this engine handles no
//! preemption. These model-checked
//! encodings do not establish full GT setup, safe userspace execution,
//! silicon cache completion or hardware reset; the userspace gate in
//! intel_gpu_render remains closed until those owners exist.

use core::mem::ManuallyDrop;
use core::sync::atomic::{compiler_fence, fence, Ordering};

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_exec::ResidentBatch;
use crate::intel_gpu_fence::{CompletionFence, JobError};
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
    /// Absolute `RING_EXECLIST_SQ_CONTENTS` (port n at +8n, low dword
    /// first) for this engine.
    pub const fn execlist_sq(&self) -> u64 {
        self.base + 0x510
    }
    /// Absolute `RING_EXECLIST_CONTROL` for this engine.
    pub const fn execlist_control(&self) -> u64 {
        self.base + 0x550
    }
    /// Absolute `RING_CONTEXT_STATUS_PTR` for this engine.
    pub const fn context_status_ptr(&self) -> u64 {
        self.base + 0x3a0
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

/// Gen12 render retirement: drain HDC, tile, render, depth and data caches
/// before a separate GGTT post-sync write. Includes Wa_1409600907 depth
/// stall for TGL/ADL. MIT i915 v6.12 gen8_engine_cs.c/h and
/// intel_gpu_commands.h define these fields; this is not an Xe-LPG stream.
fn render_breadcrumb(address: u64, seqno: u32) -> [u32; 12] {
    [
        0x7a00_0204, // PIPE_CONTROL(6), HDC pipeline flush
        0x1814_30a1, // CS/depth stall, TLB invalidate, cache flushes
        0,
        0,
        0,
        0,
        0x7a00_0004,
        0x0110_4080, // CS stall, flush, QW post-sync write through GGTT
        address as u32,
        (address >> 32) as u32,
        seqno,
        0,
    ]
}

/// `GFX_OP_PIPE_CONTROL(6)`.
const PIPE_CONTROL6: u32 = 0x7a00_0004;
/// `MI_ARB_CHECK`.
const MI_ARB_CHECK: u32 = 0x0280_0000;
/// `MI_USER_INTERRUPT`.
const MI_USER_INTERRUPT: u32 = 0x0100_0000;
/// `MI_SEMAPHORE_WAIT | MI_SEMAPHORE_GLOBAL_GTT | MI_SEMAPHORE_POLL |
/// MI_SEMAPHORE_SAD_EQ_SDD`: poll a GGTT dword until it equals the data.
const MI_SEMAPHORE_WAIT_POLL_EQ: u32 = 0x0e00_0002 | 1 << 22 | 1 << 15 | 4 << 12;
/// `I915_GEM_HWS_PREEMPT`: the engine status page dword every Gen9/Gen11
/// request's breadcrumb busywaits on while it is set (`ring_set_paused`).
pub(crate) const HWS_PREEMPT_BYTE: u64 = 0x32 * 4;
/// `CONFIG_DRM_I915_TIMESLICE_DURATION`: how long ELSP[0] runs while
/// another context waits before the engine rotates.
pub const TIMESLICE_NS: u64 = 1_000_000;

/// `gen8_emit_bb_start`: arbitration on across the batch, so the engine
/// can be preempted at its arbitration points, then off again.
fn legacy_bb_start(words: &mut Vec<u32>, start: [u32; 3]) {
    words.push(MI_ARB_ENABLE);
    words.extend_from_slice(&start);
    words.extend_from_slice(&[MI_ARB_DISABLE, MI_NOOP]);
}

/// `gen8_emit_fini_breadcrumb_tail` and `gen8_emit_wa_tail`: the user
/// interrupt, arbitration on, `emit_preempt_busywait` on `preempt` (the
/// engine status page's `I915_GEM_HWS_PREEMPT`), and the arbitration point
/// and NOOP `WaIdleLiteRestore` reserves.
fn legacy_fini_tail(words: &mut Vec<u32>, preempt: u32) {
    words.extend_from_slice(&[
        MI_USER_INTERRUPT,
        MI_ARB_ENABLE,
        MI_ARB_CHECK,
        MI_SEMAPHORE_WAIT_POLL_EQ,
        0,
        preempt,
        0,
        MI_NOOP,
        MI_ARB_CHECK,
        MI_NOOP,
    ]);
}
/// `LRC_PPHWSP_SCRATCH_ADDR`: the per-context HWSP scratch dword the
/// invalidate's store-data-index post-sync lands in.
const PPHWSP_SCRATCH: u32 = 0x34 * 4;

/// One Gen9/Gen11 render request, MIT Linux v6.12 `gen8_engine_cs.c`:
/// `gen8_emit_flush_rcs` / `gen11_emit_flush_rcs` with `EMIT_INVALIDATE`
/// (Gen9 first emits the null PIPE_CONTROL its VF invalidate needs), the
/// preemptible `gen8_emit_bb_start`, then `gen8_emit_fini_breadcrumb_rcs` /
/// `gen11_...`: a cache-flush PIPE_CONTROL (Gen11 adds the tile cache), the
/// GGTT QW seqno write and the breadcrumb tail busywaiting on `preempt`.
/// The KBL-before-C0 DC flush workaround is not emitted (pre-production
/// steppings only).
fn legacy_render_request(
    gen11: bool,
    start: [u32; 3],
    address: u64,
    seqno: u32,
    preempt: u32,
) -> Vec<u32> {
    let mut words = Vec::with_capacity(40);
    if !gen11 {
        words.extend_from_slice(&[PIPE_CONTROL6, 0, 0, 0, 0, 0]);
    }
    // CS stall, TLB / instruction / texture / VF / constant / state cache
    // invalidate, QW write with store-data-index (Gen11: command cache).
    let invalidate = 0x0034_4c1c | if gen11 { 1 << 29 } else { 0 };
    words.extend_from_slice(&[PIPE_CONTROL6, invalidate, PPHWSP_SCRATCH, 0, 0, 0]);
    legacy_bb_start(&mut words, start);
    // CS stall, TLB invalidate, render target / depth / DC flush (Gen11:
    // tile cache flush).
    let flush = 0x0014_1021 | if gen11 { 1 << 28 } else { 0 };
    words.extend_from_slice(&[PIPE_CONTROL6, flush, 0, 0, 0, 0]);
    // Flush enable, CS stall, global GTT, QW write.
    words.extend_from_slice(&[
        PIPE_CONTROL6,
        0x0110_4080,
        address as u32,
        (address >> 32) as u32,
        seqno,
        0,
    ]);
    legacy_fini_tail(&mut words, preempt);
    words
}

/// One Gen9/Gen11 copy or media request, MIT Linux v6.12
/// `gen8_engine_cs.c`: `gen8_emit_flush_xcs` with `EMIT_INVALIDATE` (TLB,
/// plus the BSD cache on video decode, with a store-index write to the
/// PPHWSP scratch as its command barrier), the preemptible
/// `gen8_emit_bb_start`, then `gen8_emit_fini_breadcrumb_xcs`'s GGTT seqno
/// write and the breadcrumb tail busywaiting on `preempt`. Each resident
/// batch brings its own PPGTT, so the TLB invalidate is what keeps a
/// previous job's translations out.
fn legacy_xcs_request(
    video: bool,
    start: [u32; 3],
    address: u64,
    seqno: u32,
    preempt: u32,
) -> Vec<u32> {
    // MI_FLUSH_DW (4 dwords) | STORE_INDEX | OP_STOREDW | INVALIDATE_TLB,
    // plus INVALIDATE_BSD on VCS.
    let invalidate = 0x1300_0002 | 1 << 21 | 1 << 14 | 1 << 18 | if video { 1 << 7 } else { 0 };
    let mut words = Vec::with_capacity(24);
    words.extend_from_slice(&[invalidate, PPHWSP_SCRATCH, 0, 0]);
    legacy_bb_start(&mut words, start);
    // MI_FLUSH_DW | OP_STOREDW, GGTT address (USE_GTT), seqno.
    words.extend_from_slice(&[
        0x1300_4002,
        address as u32 | 4,
        (address >> 32) as u32,
        seqno,
    ]);
    legacy_fini_tail(&mut words, preempt);
    words
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
///
/// This is the Gen11+ form; [`context_descriptor_for_generation`]
/// selects the Gen9 layout for `Generation::Skylake`.
pub fn context_descriptor_for(spec: &EngineSpec, lrca: u32, sw_ctx_id: u16) -> u64 {
    context_descriptor_for_generation(
        spec,
        lrca,
        sw_ctx_id,
        crate::intel_gpu::Generation::TigerLake,
    )
}

/// Build the 64-bit execlists context descriptor for the
/// generation `generation` (MIT `intel_lrc.c`
/// `lrc_descriptor` + `__execlists_schedule_in`).
///
/// The low dword is shared: valid, Legacy-64B mode, privileged,
/// LRCA. The upper dword differs by generation — that is the
/// Gen9-vs-Gen11+ difference the audit asserted without a
/// citation, grounded here against the 7.4-rc2 source:
///
/// - Gen11+ packs the SW context id at bits 37:47, the engine
///   instance at bits 48:53 and the engine class at bits 61:63
///   (`intel_lrc.h` `GEN11_SW_CTX_ID_SHIFT` 37,
///   `GEN11_ENGINE_INSTANCE_SHIFT` 48,
///   `GEN11_ENGINE_CLASS_SHIFT` 61; the instance/class halves
///   are ORed into the descriptor's upper dword from the
///   engine's execlists cookie, `intel_execlists_submission.c`,
///   only for graphics 11..12.55).
/// - Gen9 (graphics 9) carries the SW context id at bits 37:47
///   and nothing else above it: the tag is placed there by
///   `__execlists_schedule_in` on every pre-XeHP generation
///   (`(1 + tag) << (GEN11_SW_CTX_ID_SHIFT - 32)`), and the
///   instance/class OR is skipped below graphics 11, so the
///   remaining upper-dword bits are the pre-Gen11 21-bit context
///   ID field's zero padding (group ID 0, `intel_lrc.c`
///   descriptor comment). The SW-id extraction
///   ([`descriptor_sw_id`]) is therefore the same on Gen9,
///   and the CSB "switched to/away" fields name the SW id on
///   both generations (Linux parses both with the same
///   `gen8_csb_parse`).
///
/// The low dword keeps `DESC_L3LLC_COHERENT` set on Gen9, as
/// on Gen11/Gen12: Linux `lrc_descriptor` sets it only for
/// graphics 8, but the Gen11 lane recorded that as a deliberate
/// NARF-wide deviation in the spec (§8) rather than diverging
/// on an untested hunch, and this lane keeps Gen9 under the
/// same policy. First silicon decides whether the bit is
/// honored or ignored on Gen9.
pub fn context_descriptor_for_generation(
    spec: &EngineSpec,
    lrca: u32,
    sw_ctx_id: u16,
    generation: crate::intel_gpu::Generation,
) -> u64 {
    debug_assert!(lrca & 0xFFF == 0);
    debug_assert!(sw_ctx_id < IDLE_SW_ID);
    debug_assert!(spec.instance < 64);
    let lo = DESC_VALID
        | DESC_MODE_LEGACY_64B
        | DESC_L3LLC_COHERENT
        | DESC_PRIVILEGE
        | (lrca as u64 & 0xFFFF_F000);
    let mut hi = ((sw_ctx_id as u64) & 0x7FF) << 5;
    if !matches!(generation, crate::intel_gpu::Generation::Skylake) {
        hi |= ((spec.instance as u64) & 0x3F) << 16;
        hi |= spec.class.descriptor_value() << 29;
    }
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
/// Gen11 `CTX_BB_PER_CTX_PTR` pair index. The Gen11 first
/// group carries the second-level batch registers Gen12 drops,
/// so the workaround-batch pair sits six dwords later than on
/// Gen12 (MIT `intel_lrc.c` `gen11_rcs_offsets` /
/// `gen9_xcs_offsets`).
pub const GEN11_CTX_BB_PER_CTX_PTR: usize = 0x18;
/// Gen11 `CTX_RCS_INDIRECT_CTX` pair index.
pub const GEN11_CTX_RCS_INDIRECT_CTX: usize = 0x1A;
/// Gen11 `CTX_RCS_INDIRECT_CTX_OFFSET` pair index.
pub const GEN11_CTX_RCS_INDIRECT_CTX_OFFSET: usize = 0x1C;
/// Gen11 render context restore terminator (the template ends
/// after the `R_PWR_CLK_STATE` pair — there is no 51-register
/// extended group on Gen11).
pub const GEN11_CTX_RCS_END: usize = 0x44;
/// Gen11 non-render context restore terminator (the template
/// ends after the 44-register group).
pub const GEN11_CTX_XCS_END: usize = 0xAA;
/// `RING_INDIRECT_CTX_OFFSET` default for Gen9 (MIT
/// `intel_lrc_reg.h` `GEN9_CTX_RCS_INDIRECT_CTX_OFFSET_DEFAULT`).
pub const GEN9_INDIRECT_CTX_OFFSET_DEFAULT: u32 = 0x26;
/// `RING_INDIRECT_CTX_OFFSET` default for Gen11 (MIT
/// `intel_lrc_reg.h` `GEN11_CTX_RCS_INDIRECT_CTX_OFFSET_DEFAULT`).
pub const GEN11_INDIRECT_CTX_OFFSET_DEFAULT: u32 = 0x1A;
/// `RING_INDIRECT_CTX_OFFSET` default for Gen12 (MIT
/// `intel_lrc_reg.h` `GEN12_CTX_RCS_INDIRECT_CTX_OFFSET_DEFAULT`).
pub const GEN12_INDIRECT_CTX_OFFSET_DEFAULT: u32 = 0x0D;

/// The `RING_INDIRECT_CTX_OFFSET` default for `generation`:
/// the value Linux programs (`<< 6`, per
/// `intel_lrc.c::lrc_setup_indirect_ctx`) when an indirect
/// context exists. Only the Gen11 template programs it today
/// (the task's per-generation dispatch); Gen12 keeps its
/// existing zero template value. Either way the value is inert
/// until an indirect batch exists — Linux programs it only
/// alongside one (`lrc_init_wa_ctx` returns early for graphics
/// 11, and the per-context WA page is Gen12+ only) — and the
/// pointer slot stays zero on both generations.
pub const fn indirect_ctx_offset_default(generation: crate::intel_gpu::Generation) -> u32 {
    match generation {
        crate::intel_gpu::Generation::Skylake => GEN9_INDIRECT_CTX_OFFSET_DEFAULT,
        crate::intel_gpu::Generation::IceLake => GEN11_INDIRECT_CTX_OFFSET_DEFAULT,
        _ => GEN12_INDIRECT_CTX_OFFSET_DEFAULT,
    }
}
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

/// The `CONTEXT_CONTROL` value for `generation` (MIT
/// `intel_lrc.c` `init_common_regs`): Gen11+ takes
/// [`CTX_CONTROL_VALUE`]; Gen9 (graphics < 11) additionally
/// masked-disables the save-inhibit (bit 2) and render-state
/// context-enable (bit 1) fields (`intel_engine_regs.h`
/// `CTX_CTRL_ENGINE_CTX_SAVE_INHIBIT` /
/// `CTX_CTRL_RS_CTX_ENABLE`), so its value is 0xF0008 rather
/// than 0x90008.
pub const fn ctx_control_value(generation: crate::intel_gpu::Generation) -> u32 {
    match generation {
        crate::intel_gpu::Generation::Skylake => {
            const SAVE_INHIBIT: u32 = 1 << 2;
            const RS_CTX_ENABLE: u32 = 1 << 1;
            CTX_CONTROL_VALUE | ((SAVE_INHIBIT | RS_CTX_ENABLE) << 16)
        }
        _ => CTX_CONTROL_VALUE,
    }
}

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
/// This is the Gen12 form; [`build_reg_state_for_generation`]
/// selects the Gen9 layout for `Generation::Skylake` and the
/// Gen11 layout for `Generation::IceLake`.
pub fn build_reg_state_for(
    spec: &EngineSpec,
    ring_ggtt: u32,
    ring_bytes: u32,
) -> [u32; REG_STATE_DWORDS] {
    build_reg_state_for_generation(
        spec,
        ring_ggtt,
        ring_bytes,
        crate::intel_gpu::Generation::TigerLake,
    )
}

/// Build the register-state template for a fresh context on
/// the engine `spec` names for the generation `generation`.
/// Gen9 (`Generation::Skylake`) takes the Gen9 layout
/// ([`build_gen9_reg_state`]); Gen11 (`Generation::IceLake`)
/// takes the Gen11 layout ([`build_gen11_reg_state`]); every
/// other generation keeps the existing Gen12-shaped template
/// (the MTL+ tables are their own Linux tables and out of scope
/// here).
pub fn build_reg_state_for_generation(
    spec: &EngineSpec,
    ring_ggtt: u32,
    ring_bytes: u32,
    generation: crate::intel_gpu::Generation,
) -> [u32; REG_STATE_DWORDS] {
    if matches!(generation, crate::intel_gpu::Generation::Skylake) {
        return build_gen9_reg_state(spec, ring_ggtt, ring_bytes);
    }
    if matches!(generation, crate::intel_gpu::Generation::IceLake) {
        return build_gen11_reg_state(spec, ring_ggtt, ring_bytes);
    }
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

/// The 44-register extended group shared by the Gen9 RCS/XCS
/// tables and the Gen11 XCS table (MIT `intel_lrc.c`
/// `gen9_rcs_offsets` / `gen9_xcs_offsets`, the trailing group
/// of both; the Gen12 extended list without the six `0x588`
/// repeats and the trailing `0x84`).
const XCS44: [u32; 44] = [
    0x28, 0x9c, 0xc0, 0x178, 0x17c, 0x358, 0x170, 0x150, 0x154, 0x158, 0x41c, 0x600, 0x604, 0x608,
    0x60c, 0x610, 0x614, 0x618, 0x61c, 0x620, 0x624, 0x628, 0x62c, 0x630, 0x634, 0x638, 0x63c,
    0x640, 0x644, 0x648, 0x64c, 0x650, 0x654, 0x658, 0x65c, 0x660, 0x664, 0x668, 0x66c, 0x670,
    0x674, 0x678, 0x67c, 0x68,
];

/// Gen11 register-state template (MIT `intel_lrc.c`:
/// `gen11_rcs_offsets` for render, `gen9_xcs_offsets` for
/// everything else — Gen11 has no own XCS table; `reg_offsets`
/// falls back to the Gen9 one for non-RCS engines on Gen9–11).
///
/// Deltas from the Gen12 template, transcribed from those
/// tables rather than re-derived:
/// - The first group is 15 (RCS) / 14 (XCS) pairs and carries
///   the second-level batch registers (`RING_SBBADDR_UDW` 0x11c,
///   `RING_SBBADDR` 0x114, `RING_SBBSTATE` 0x118) Gen12 drops,
///   with no `0x2b4` tail register; XCS also omits the trailing
///   `0x180`. The SBB registers shift the workaround-batch and
///   indirect-context pairs to the `GEN11_CTX_*` indices.
/// - The third group is a single `0x1b0` pair on RCS. XCS has
///   no third group and instead carries the `0x200` pair at
///   0x42, then the 44-register group at 0x51 — the Gen12
///   extended list without the six `0x588` repeats and the
///   trailing `0x84`.
/// - There is no 51-register extended group on RCS: the render
///   template ends after the `R_PWR_CLK_STATE` pair at
///   `GEN11_CTX_RCS_END` (0x44).
/// - The indirect-context offset value is Gen11's 0x1a,
///   programmed `<< 6` per `lrc_setup_indirect_ctx`.
fn build_gen11_reg_state(
    spec: &EngineSpec,
    ring_ggtt: u32,
    ring_bytes: u32,
) -> [u32; REG_STATE_DWORDS] {
    let b = spec.base;
    let mut r = [0u32; REG_STATE_DWORDS];
    const RELATIVE: u32 = 1 << 19;
    let first: &[u32] = if spec.has_pwr_clk_state() {
        &[
            0x244, 0x34, 0x30, 0x38, 0x3c, 0x168, 0x140, 0x110, 0x11c, 0x114, 0x118, 0x1c0, 0x1c4,
            0x1c8, 0x180,
        ]
    } else {
        &[
            0x244, 0x34, 0x30, 0x38, 0x3c, 0x168, 0x140, 0x110, 0x11c, 0x114, 0x118, 0x1c0, 0x1c4,
            0x1c8,
        ]
    };
    r[CTX_LRI_HEADER_0] = mi_load_register_imm(first.len() as u32, true) | RELATIVE;
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
        r[0x41] = mi_load_register_imm(1, true) | RELATIVE;
        r[0x42] = b as u32 + 0x200;
        // Transcribed from `gen9_xcs_offsets`: the Gen12
        // extended list without the six 0x588 repeats and the
        // trailing 0x84 (see [`XCS44`]).
        r[0x51] = mi_load_register_imm(44, true) | RELATIVE;
        for (i, offset) in XCS44.iter().enumerate() {
            r[0x52 + i * 2] = b as u32 + offset;
        }
        r[GEN11_CTX_XCS_END] = MI_BATCH_BUFFER_END | 1;
        return r;
    }
    // RCS only: the indirect-context offset default, programmed
    // in the value slot of the shifted offset pair (see
    // `GEN11_CTX_RCS_INDIRECT_CTX_OFFSET`). The pointer slot
    // stays zero — Gen11 has no indirect-context batch.
    r[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] = GEN11_INDIRECT_CTX_OFFSET_DEFAULT << 6;
    r[0x34] = mi_load_register_imm(1, true) | RELATIVE;
    r[0x35] = b as u32 + 0x1b0;
    r[CTX_LRI_HEADER_2] = mi_load_register_imm(1, false) | RELATIVE;
    r[CTX_R_PWR_CLK_STATE] = R_PWR_CLK_STATE as u32;
    r[GEN11_CTX_RCS_END] = MI_BATCH_BUFFER_END | 1;
    r
}

/// Gen9 register-state template (MIT `intel_lrc.c`:
/// `gen9_rcs_offsets` for render, `gen9_xcs_offsets` for
/// everything else — the table the Gen11 XCS half already
/// reuses).
///
/// Transcribed, not re-derived, and diffed against
/// [`build_gen11_reg_state`]. The first groups look
/// near-identical (both start `LRI(14, POSTED)` with the same
/// 0x244/0x34/0x30/… sequence); the divergence is in the later
/// groups:
///
/// - The first group is 14 pairs on RCS as well as XCS: Gen9
///   RCS has no trailing `0x180` pair, so the workaround-batch
///   and indirect-context pairs sit at the same
///   `GEN11_CTX_*` indices as the Gen11 XCS first group.
/// - There is no `0x1b0` third group: Gen9 RCS goes straight
///   from the PDP group to the single-pair
///   `R_PWR_CLK_STATE` group (`LRI(1, 0)`, engine-relative
///   `0xc8`, at `CTX_LRI_HEADER_2` / `CTX_R_PWR_CLK_STATE`).
/// - Unlike Gen11 RCS, Gen9 RCS does NOT end there: it
///   carries the full 44-register extended group at 0x51 and
///   ends at dword 0xaa — the same terminator as XCS. The
///   44-register list is [`XCS44`], identical in both tables.
/// - The indirect-context offset value is Gen9's 0x26,
///   programmed `<< 6` per `lrc_setup_indirect_ctx`.
/// - The LRI headers carry NO `MI_LRI_LRM_CS_MMIO` bit
///   (`RELATIVE`): Linux `set_offsets` sets it only for
///   graphics 11+, so Gen9 headers are the bare
///   `mi_load_register_imm` encoding.
/// - The context-control value is Gen9's
///   [`ctx_control_value`] (0xF0008, with the pre-11
///   save-inhibit / RS-context-enable disables).
fn build_gen9_reg_state(
    spec: &EngineSpec,
    ring_ggtt: u32,
    ring_bytes: u32,
) -> [u32; REG_STATE_DWORDS] {
    let b = spec.base;
    let mut r = [0u32; REG_STATE_DWORDS];
    // The 14-pair first group is the same on RCS and XCS
    // (`gen9_rcs_offsets` / `gen9_xcs_offsets` agree here).
    const FIRST: [u32; 14] = [
        0x244, 0x34, 0x30, 0x38, 0x3c, 0x168, 0x140, 0x110, 0x11c, 0x114, 0x118, 0x1c0, 0x1c4,
        0x1c8,
    ];
    r[CTX_LRI_HEADER_0] = mi_load_register_imm(FIRST.len() as u32, true);
    for (i, offset) in FIRST.iter().enumerate() {
        r[2 + i * 2] = b as u32 + offset;
    }
    r[CTX_CONTEXT_CONTROL + 1] = ctx_control_value(crate::intel_gpu::Generation::Skylake);
    r[CTX_RING_BUFFER_START + 1] = ring_ggtt;
    r[CTX_RING_BUFFER_CONTROL + 1] = ring_ctl_value(ring_bytes);
    r[CTX_LRI_HEADER_1] = mi_load_register_imm(9, true);
    r[CTX_CTX_TIMESTAMP] = (b + 0x3a8) as u32;
    for i in 0..4u32 {
        let at = CTX_PDP3_UDW + i as usize * 4;
        r[at] = ring_pdp_udw_at(b, 3 - i) as u32;
        r[at + 2] = ring_pdp_ldw_at(b, 3 - i) as u32;
    }
    if !spec.has_pwr_clk_state() {
        r[0x41] = mi_load_register_imm(1, true);
        r[0x42] = b as u32 + 0x200;
        r[0x51] = mi_load_register_imm(44, true);
        for (i, offset) in XCS44.iter().enumerate() {
            r[0x52 + i * 2] = b as u32 + offset;
        }
        r[GEN11_CTX_XCS_END] = MI_BATCH_BUFFER_END | 1;
        return r;
    }
    // RCS only: the indirect-context offset default, programmed
    // in the value slot of the shifted offset pair (see
    // `GEN11_CTX_RCS_INDIRECT_CTX_OFFSET`). The pointer slot
    // stays zero until the WA batch is wired (see
    // [`setup_gen9_indirect_ctx`]).
    r[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] = GEN9_INDIRECT_CTX_OFFSET_DEFAULT << 6;
    r[0x41] = mi_load_register_imm(1, false);
    r[0x42] = b as u32 + 0xC8;
    r[0x51] = mi_load_register_imm(44, true);
    for (i, offset) in XCS44.iter().enumerate() {
        r[0x52 + i * 2] = b as u32 + offset;
    }
    r[GEN11_CTX_XCS_END] = MI_BATCH_BUFFER_END | 1;
    r
}

/// Build the RCS0 register-state template (the historical form
/// of [`build_reg_state_for`]).
pub fn build_reg_state(ring_ggtt: u32, ring_bytes: u32) -> [u32; REG_STATE_DWORDS] {
    build_reg_state_for(&RCS0_SPEC, ring_ggtt, ring_bytes)
}

// ── Gen9 indirect-context workaround batch ────────────────────
//
// Linux `gt/intel_lrc.c` `gen9_init_indirectctx_bb` (wired by
// `lrc_init_wa_ctx` for graphics 9 only — it returns early for
// graphics 11+). The batch runs once per context switch, before
// the context's own commands, with arbitration disabled; it
// applies the Gen9 context-switch workarounds that cannot live
// in the register-state template. No WA-batch function existed
// in NARF before this lane.

/// `MI_ARB_ON_OFF` (MIT `intel_gpu_commands.h`).
pub const MI_ARB_ON_OFF: u32 = 0x08 << 23;
/// `MI_ARB_DISABLE` — arbitration off for the WA batch.
pub const MI_ARB_DISABLE: u32 = MI_ARB_ON_OFF;
/// `MI_ARB_ENABLE` — arbitration back on at the end of the batch.
pub const MI_ARB_ENABLE: u32 = MI_ARB_ON_OFF | 1;

/// `GEN8_L3SQCREG4` (MIT `intel_gt_regs.h`, 0xb118).
pub const GEN8_L3SQCREG4: u32 = 0xB118;
/// `GEN8_LQSC_FLUSH_COHERENT_LINES` (bit 21 of `GEN8_L3SQCREG4`).
pub const GEN8_LQSC_FLUSH_COHERENT_LINES: u32 = 1 << 21;

/// `MI_STORE_REGISTER_MEM_GEN8` (MIT `intel_gpu_commands.h`).
pub const MI_STORE_REGISTER_MEM_GEN8: u32 = (0x24 << 23) | 2;
/// `MI_LOAD_REGISTER_MEM_GEN8`.
pub const MI_LOAD_REGISTER_MEM_GEN8: u32 = (0x29 << 23) | 2;
/// `MI_SRM_LRM_GLOBAL_GTT` — the save/restore address is a GGTT
/// address, not a physical one.
pub const MI_SRM_LRM_GLOBAL_GTT: u32 = 1 << 22;

/// `GFX_OP_PIPE_CONTROL(6)` (MIT `intel_gpu_commands.h`).
pub const PIPE_CONTROL_HEADER: u32 = 0x7A00_0004;
/// `PIPE_CONTROL_FLUSH_L3` (bit 27).
pub const PIPE_CONTROL_FLUSH_L3: u32 = 1 << 27;
/// `PIPE_CONTROL_STORE_DATA_INDEX` (bit 21).
pub const PIPE_CONTROL_STORE_DATA_INDEX: u32 = 1 << 21;
/// `PIPE_CONTROL_CS_STALL` (bit 20).
pub const PIPE_CONTROL_CS_STALL: u32 = 1 << 20;
/// `PIPE_CONTROL_QW_WRITE` (bit 14).
pub const PIPE_CONTROL_QW_WRITE: u32 = 1 << 14;
/// `PIPE_CONTROL_DC_FLUSH_ENABLE` (bit 5).
pub const PIPE_CONTROL_DC_FLUSH_ENABLE: u32 = 1 << 5;

/// Per-context HWSP scratch dword address
/// (`LRC_PPHWSP_SCRATCH_ADDR` = 0x34 * 4 = 0xd0, MIT
/// `intel_lrc.h`).
pub const LRC_PPHWSP_SCRATCH_ADDR: u32 = 0xD0;

/// `COMMON_SLICE_CHICKEN2` (MIT `intel_gt_regs.h`, 0x7014).
pub const COMMON_SLICE_CHICKEN2: u32 = 0x7014;
/// `GEN9_DISABLE_GATHER_AT_SET_SHADER_COMMON_SLICE` (bit 12).
pub const GEN9_DISABLE_GATHER_AT_SET_SHADER_COMMON_SLICE: u32 = 1 << 12;
/// `FF_SLICE_CHICKEN` (MIT `intel_gt_regs.h`, 0x2088).
pub const FF_SLICE_CHICKEN: u32 = 0x2088;
/// `FF_SLICE_CHICKEN_CL_PROVOKING_VERTEX_FIX` (bit 1).
pub const FF_SLICE_CHICKEN_CL_PROVOKING_VERTEX_FIX: u32 = 1 << 1;
/// `_3D_CHICKEN3` (MIT `intel_gt_regs.h`, 0x2090).
pub const CHICKEN3_3D: u32 = 0x2090;
/// `_3D_CHICKEN_SF_PROVOKING_VERTEX_FIX` (bit 12).
pub const CHICKEN3_SF_PROVOKING_VERTEX_FIX: u32 = 1 << 12;

/// `GEN9_MEDIA_POOL_STATE` (MIT `intel_gpu_commands.h`).
pub const GEN9_MEDIA_POOL_STATE: u32 = 0x7005_0004;
/// `GEN9_MEDIA_POOL_ENABLE` (bit 31).
pub const GEN9_MEDIA_POOL_ENABLE: u32 = 1 << 31;

/// Dwords the Gen9 indirect-context WA batch occupies at most
/// (33 dwords without the pooled-EU media-pool sequence, 39
/// with it, both padded up to a whole number of 64-byte
/// cachelines). The batch must fit in one page (Linux
/// `CTX_WA_BB_SIZE` is a page); the caller supplies a
/// `batch` slice of at least this length.
pub const GEN9_INDIRECT_CTX_BB_DWORDS: usize = 48;

/// Emit the Gen9 indirect-context workaround batch
/// (`gen9_init_indirectctx_bb`) into `batch`, returning the
/// number of dwords written (always a multiple of 16 — the
/// batch is padded with `MI_NOOP` to the end of its last
/// cacheline, as Linux pads to the end of the cacheline; no
/// `MI_BATCH_BUFFER_END` is emitted, because execution length
/// comes from the cacheline count in `CTX_RCS_INDIRECT_CTX`).
///
/// Layout, in order:
/// - `MI_ARB_DISABLE`.
/// - `WaFlushCoherentL3CacheLinesAtContextSwitch` (skl/bxt/glk):
///   save `GEN8_L3SQCREG4` to the GT scratch dword
///   `gt_scratch_ggtt`, load it with `0x40400000 |
///   GEN8_LQSC_FLUSH_COHERENT_LINES`, a pipe-control
///   (CS-stall + DC-flush), then restore the saved value.
/// - `WaClearSlmSpaceAtContextSwitch` (skl/bxt/kbl/glk/cfl):
///   a pipe-control (flush-L3 + store-data-index + CS-stall +
///   QW-write) to the per-context HWSP scratch address.
/// - `WaDisableGatherAtSetShaderCommonSlice` (skl/bxt/kbl/glk),
///   the FF-slice provoking-vertex fix (BSpec 11391) and the
///   3D-chicken provoking-vertex fix (BSpec 11299), as one
///   non-posted `MI_LOAD_REGISTER_IMM(3)` group plus a trailing
///   `MI_NOOP` (Linux `emit_lri`).
/// - On pooled-EU parts (`pooled_eu`, Linux `HAS_POOLED_EU` —
///   BXT/GLK only in the Gen9 family, `WaMediaPoolStateCmdInWABB`):
///   `GEN9_MEDIA_POOL_STATE` / `GEN9_MEDIA_POOL_ENABLE` /
///   `0x00777000` / 0 / 0 / 0.
/// - `MI_ARB_ENABLE`.
///
/// `gt_scratch_ggtt` is the GGTT address of the GT scratch
/// dword reserved for the coherent-L3 save/restore (Linux
/// `INTEL_GT_SCRATCH_FIELD_COHERENTL3_WA`, GT scratch + 256 —
/// "no one else is allowed to scribble over scratch + 256").
/// NARF has no GT scratch allocation yet, so the caller
/// supplies the address; the engine bring-up that owns the WA
/// page (follow-up) will own it. The batch is inert until that
/// bring-up programs the indirect-context pointer/offset pair
/// (see [`setup_gen9_indirect_ctx`]).
///
/// Panics if `batch` is shorter than
/// [`GEN9_INDIRECT_CTX_BB_DWORDS`].
pub fn gen9_init_indirectctx_bb(batch: &mut [u32], pooled_eu: bool, gt_scratch_ggtt: u32) -> usize {
    assert!(batch.len() >= GEN9_INDIRECT_CTX_BB_DWORDS);
    let mut n = 0usize;
    // MI_ARB_ON_OFF | MI_ARB_DISABLE.
    batch[n] = MI_ARB_DISABLE;
    n += 1;
    // gen8_emit_flush_coherentl3_wa: MI_STORE_REGISTER_MEM_GEN8
    // (global-GTT) saves GEN8_L3SQCREG4 to the scratch dword.
    batch[n] = MI_STORE_REGISTER_MEM_GEN8 | MI_SRM_LRM_GLOBAL_GTT;
    batch[n + 1] = GEN8_L3SQCREG4;
    batch[n + 2] = gt_scratch_ggtt;
    batch[n + 3] = 0;
    n += 4;
    // MI_LOAD_REGISTER_IMM(1): GEN8_L3SQCREG4 =
    // 0x40400000 | GEN8_LQSC_FLUSH_COHERENT_LINES.
    batch[n] = mi_load_register_imm(1, false);
    batch[n + 1] = GEN8_L3SQCREG4;
    batch[n + 2] = 0x4040_0000 | GEN8_LQSC_FLUSH_COHERENT_LINES;
    n += 3;
    // Pipe-control (CS-stall + DC-flush).
    batch[n] = PIPE_CONTROL_HEADER;
    batch[n + 1] = PIPE_CONTROL_CS_STALL | PIPE_CONTROL_DC_FLUSH_ENABLE;
    batch[n + 2] = 0;
    batch[n + 3] = 0;
    batch[n + 4] = 0;
    batch[n + 5] = 0;
    n += 6;
    // MI_LOAD_REGISTER_MEM_GEN8 (global-GTT) restores the saved
    // GEN8_L3SQCREG4 value.
    batch[n] = MI_LOAD_REGISTER_MEM_GEN8 | MI_SRM_LRM_GLOBAL_GTT;
    batch[n + 1] = GEN8_L3SQCREG4;
    batch[n + 2] = gt_scratch_ggtt;
    batch[n + 3] = 0;
    n += 4;
    // gen8_emit_pipe_control: WaClearSlmSpaceAtContextSwitch.
    batch[n] = PIPE_CONTROL_HEADER;
    batch[n + 1] = PIPE_CONTROL_FLUSH_L3
        | PIPE_CONTROL_STORE_DATA_INDEX
        | PIPE_CONTROL_CS_STALL
        | PIPE_CONTROL_QW_WRITE;
    batch[n + 2] = LRC_PPHWSP_SCRATCH_ADDR;
    batch[n + 3] = 0;
    batch[n + 4] = 0;
    batch[n + 5] = 0;
    n += 6;
    // emit_lri: the three chicken fixes, non-posted.
    batch[n] = mi_load_register_imm(3, false);
    batch[n + 1] = COMMON_SLICE_CHICKEN2;
    batch[n + 2] = GEN9_DISABLE_GATHER_AT_SET_SHADER_COMMON_SLICE << 16;
    batch[n + 3] = FF_SLICE_CHICKEN;
    batch[n + 4] =
        (FF_SLICE_CHICKEN_CL_PROVOKING_VERTEX_FIX << 16) | FF_SLICE_CHICKEN_CL_PROVOKING_VERTEX_FIX;
    batch[n + 5] = CHICKEN3_3D;
    batch[n + 6] = (CHICKEN3_SF_PROVOKING_VERTEX_FIX << 16) | CHICKEN3_SF_PROVOKING_VERTEX_FIX;
    batch[n + 7] = MI_NOOP;
    n += 8;
    // WaMediaPoolStateCmdInWABB: pooled-EU parts only.
    if pooled_eu {
        batch[n] = GEN9_MEDIA_POOL_STATE;
        batch[n + 1] = GEN9_MEDIA_POOL_ENABLE;
        batch[n + 2] = 0x0077_7000;
        batch[n + 3] = 0;
        batch[n + 4] = 0;
        batch[n + 5] = 0;
        n += 6;
    }
    // MI_ARB_ON_OFF | MI_ARB_ENABLE.
    batch[n] = MI_ARB_ENABLE;
    n += 1;
    // Pad to the end of the cacheline with MI_NOOP.
    while n % 16 != 0 {
        batch[n] = MI_NOOP;
        n += 1;
    }
    n
}

/// Program the Gen9 indirect-context pair of a built register
/// state `regs` (MIT `intel_lrc.c` `lrc_setup_indirect_ctx`):
/// the pointer slot (`GEN11_CTX_RCS_INDIRECT_CTX`, index 0x1a —
/// the same index on Gen9, `lrc_ring_indirect_ptr`) takes the
/// WA batch's GGTT address ORed with its length in cachelines,
/// and the offset slot (`GEN11_CTX_RCS_INDIRECT_CTX_OFFSET`,
/// index 0x1c) takes the Gen9 default `0x26 << 6`.
///
/// `size_bytes` must be a nonzero multiple of 64 (one
/// cacheline). The WA batch's owning bring-up (follow-up: the
/// GGTT-resident WA page allocation + `lrc_init_wa_ctx`
/// equivalent) calls this after [`gen9_init_indirectctx_bb`];
/// until then the template's pointer slot stays zero and the
/// offset value in the template is inert.
pub fn setup_gen9_indirect_ctx(
    regs: &mut [u32; REG_STATE_DWORDS],
    wa_bb_ggtt: u32,
    size_bytes: u32,
) {
    debug_assert!(size_bytes != 0 && size_bytes % 64 == 0);
    regs[GEN11_CTX_RCS_INDIRECT_CTX + 1] = wa_bb_ggtt | (size_bytes / 64);
    regs[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] = GEN9_INDIRECT_CTX_OFFSET_DEFAULT << 6;
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

/// Dword index of the CSB write pointer on Gen9 (i915
/// `I915_HWS_CSB_WRITE_INDEX`, 0x1f — the Gen11+ 0x2f location
/// above is `ICL_HWS_CSB_WRITE_INDEX`, selected by
/// `INTEL_HWS_CSB_WRITE_INDEX` only for graphics 11+;
/// `intel_engine.h:201-205`).
pub const GEN9_CSB_WRITE_DWORD: u64 = 0x1F;
/// Number of CSB entries the Gen9 hardware rotates through
/// (i915 `GEN8_CSB_ENTRIES` — the write pointer "wraps around
/// after 5h", `intel_lrc_reg.h:64`).
pub const GEN9_CSB_ENTRIES: u8 = 6;

/// The CSB depth for `generation`: 6 on Gen9, 12 on Gen11+
/// (MIT `intel_lrc_reg.h` `GEN8_CSB_ENTRIES` vs
/// `GEN11_CSB_ENTRIES`; Linux `intel_execlists_submission.c`
/// picks `GEN8_CSB_ENTRIES` for graphics < 11).
pub const fn csb_entries(generation: crate::intel_gpu::Generation) -> u8 {
    match generation {
        crate::intel_gpu::Generation::Skylake => GEN9_CSB_ENTRIES,
        _ => CSB_ENTRIES,
    }
}

/// The CSB write-pointer dword index for `generation`:
/// 0x1f on Gen9, 0x2f on Gen11+ (MIT `intel_engine.h`
/// `I915_HWS_CSB_WRITE_INDEX` vs `ICL_HWS_CSB_WRITE_INDEX`).
pub const fn csb_write_dword(generation: crate::intel_gpu::Generation) -> u64 {
    match generation {
        crate::intel_gpu::Generation::Skylake => GEN9_CSB_WRITE_DWORD,
        _ => CSB_WRITE_DWORD,
    }
}

/// Byte offset of the CSB write pointer in the status page for
/// `generation`.
pub const fn csb_write_byte(generation: crate::intel_gpu::Generation) -> u64 {
    csb_write_dword(generation) * 4
}

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

/// Whether `generation` posts Gen8-format CSB entries: Linux parses
/// graphics 9 and 11 with `gen8_csb_parse` (status bits in the low dword,
/// no switched-to/away ids it relies on) and Gen12 with `gen12_csb_parse`.
pub const fn gen8_csb(generation: crate::intel_gpu::Generation) -> bool {
    matches!(
        generation,
        crate::intel_gpu::Generation::Skylake | crate::intel_gpu::Generation::IceLake
    )
}

/// Whether ports are loaded through the execlist submit queue
/// (`HAS_LOGICAL_RING_ELSQ`, graphics 11+) rather than the four-write
/// legacy ELSP. Only Gen11 takes it here: Linux uses the queue on Gen12
/// as well, but this engine's Gen12 form is fixture-only (Gen12 submits
/// through the GuC) and keeps its historical ELSP write.
pub const fn uses_submit_queue(generation: crate::intel_gpu::Generation) -> bool {
    matches!(generation, crate::intel_gpu::Generation::IceLake)
}

/// `GEN8_CTX_STATUS_IDLE_ACTIVE`.
pub const GEN8_CSB_IDLE_ACTIVE: u32 = 1 << 0;
/// `GEN8_CTX_STATUS_PREEMPTED`.
pub const GEN8_CSB_PREEMPTED: u32 = 1 << 1;

/// Classify one Gen8-format entry the way `process_csb` does with
/// `gen8_csb_parse`: idle→active or preempted promotes the pending ports
/// (a preemption also displaces the active context); any other entry
/// completes the active port 0.
pub fn gen8_csb_step(entry: &CsbEntry, any_active: bool) -> CsbStep {
    if entry.lower & GEN8_CSB_PREEMPTED != 0 && any_active {
        CsbStep::Preempt
    } else if entry.lower & (GEN8_CSB_IDLE_ACTIVE | GEN8_CSB_PREEMPTED) != 0 {
        CsbStep::Promote
    } else if any_active {
        CsbStep::Complete
    } else {
        CsbStep::Nop
    }
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
    /// probed, it is not a Gen12 part, or its PCI function/BAR
    /// belongs to another GT submission owner.
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
    /// A completion lacked its breadcrumb or saved ring head. Published
    /// objects remain pinned until a hardware owner proves reset complete.
    CompletionLost,
    /// Owned system pages could not be published to the device cache domain.
    CacheUnavailable,
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
    /// True only for a CPU mapping whose concurrent shared cache lines are
    /// coherent with the device. One-shot cache cleaning is insufficient.
    fn coherent_for_device(&self) -> bool {
        false
    }
    /// GGTT offset of the allocation's first page.
    fn ggtt_offset(&self) -> u32;
    /// Size in 4 KiB pages.
    fn size_pages(&self) -> u32;
    /// Read the dword at byte offset `byte_off` (must be
    /// 4-byte aligned and inside the allocation).
    fn read32(&self, byte_off: u64) -> u32;
    /// Write the dword at byte offset `byte_off`.
    fn write32(&self, byte_off: u64, val: u32);
    /// Physical address of page `page` when the allocation is host RAM a
    /// user CPU mapping may alias, as `xe_oa_mmap` remaps the BO's TTM
    /// pages. Device-local and model backings keep the `None` default.
    fn host_frame(&self, _page: u32) -> Option<u64> {
        None
    }
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
/// Arena size: 32 MiB. Sparse BMG EU-stall buffers consume up to 16 MiB;
/// firmware, CT and private execution objects share the remaining capacity.
pub const GGTT_ARENA_PAGES: u32 = 8192;

/// A production allocation: host frames the CPU reaches through
/// the kernel direct map and the GPU reaches through the GGTT.
pub struct FrameBacking {
    ggtt: u32,
    pages: u32,
    frames: Vec<narf_memory::frame::PhysFrame>,
    coherent: bool,
    mapped: bool,
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
    /// Clean/invalidate exclusive WB backing for one-shot firmware DMA.
    /// After a device write this is valid only if the CPU has not dirtied any
    /// line since the pre-DMA clean. It does not make live CT memory coherent.
    pub(crate) fn publish_for_device(&self) -> bool {
        crate::intel_gpu_gtt::publish_system_pages(self.frames.iter())
    }

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
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn host_frame(&self, page: u32) -> Option<u64> {
        self.frames
            .get(page as usize)
            .map(|frame| frame.start_address().raw())
    }
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
/// 8 MiB), using the Gen12 system-memory GGTT encoding (no PPGTT RW/PAT bits).
pub struct GgttArena {
    bar: narf_bus::bar::MmioRegion,
    free_list: Vec<(u32, u32)>,
    live: usize,
    live_pages: u32,
    /// GGTT virtual size implied by the BAR length (0 = the
    /// BAR length is unknown to this handle, checks skipped —
    /// production always constructs over the probed BAR).
    ggtt_va_size: u64,
    policy: Option<crate::intel_gpu_gt_hw::CachePolicy>,
    authority: Option<crate::intel_gpu_gt_hw::AuthorizedWindow>,
    gt_platform: Option<crate::intel_gpu_gt::GtPlatform>,
    lnl_receipt: Option<crate::intel_gpu_gt::lnl::Receipt>,
    bmg_authority: Option<Arc<crate::intel_gpu_gt::smallbar::Authority>>,
    lnl_device: Option<narf_bus::BusDevice>,
    lnl_pte_count: core::cell::Cell<u8>,
    retired: bool,
    live_ranges: alloc::collections::BTreeMap<u32, u32>,
    ggtt_ledger: Option<alloc::sync::Arc<crate::intel_gpu_ggtt_ranges::Ledger>>,
    /// Every GuC that may cache translations of this GGTT, and the cleared
    /// ranges held until each has invalidated past the clear
    /// (xe_ggtt.c::xe_ggtt_invalidate, both GTs). GT0's GuC is an MMIO client
    /// of every authorized arena from construction until its proven reset.
    /// No PTE is published before its owner holds the GT wake. The MTL/Arrow
    /// media GuC (GT1) registers before its firmware DMA and leaves after its
    /// verified stop. In `Mode::Ct` that GuC's scheduler invalidates over its
    /// CT.
    tlb: GuCTlbTracker,
}

type GuCTlbTracker = crate::intel_gpu_ggtt_tlb::Tracker<RetainedRange>;

/// A cleared GGTT range, kept out of the free list with its frames until
/// every GuC that may cache it has invalidated past the clear.
struct RetainedRange {
    ggtt: u32,
    pages: u32,
    frames: Vec<narf_memory::frame::PhysFrame>,
}

impl core::fmt::Debug for GgttArena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GgttArena")
            .field("free_blocks", &self.free_list.len())
            .field("live_allocations", &self.live)
            .field("live_pages", &self.live_pages)
            .field("tlb", &self.tlb)
            .finish()
    }
}

impl GgttArena {
    fn encode_pte(&self, phys: u64) -> Result<u64, crate::intel_gpu_gtt::GttError> {
        match self.policy {
            None => {
                // The unqualified arena belongs to the legacy Gen12 engine.
                // Its DMA mask is narrower than the shared GGTT wire format.
                if phys >> 39 != 0 {
                    return Err(crate::intel_gpu_gtt::GttError::PhysOutOfRange);
                }
                encode_scanout_pte(phys, PatSlot::Slot0)
            }
            Some(policy) => {
                if phys >> policy.platform().physical_bits() != 0 {
                    return Err(crate::intel_gpu_gtt::GttError::PhysOutOfRange);
                }
                let format = policy.platform().pte_format();
                format.encode_ggtt(phys, policy.ggtt_pat())
            }
        }
    }
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
            policy: None,
            authority: None,
            gt_platform: None,
            lnl_receipt: None,
            bmg_authority: None,
            lnl_device: None,
            lnl_pte_count: core::cell::Cell::new(0),
            retired: false,
            live_ranges: alloc::collections::BTreeMap::new(),
            ggtt_ledger: crate::intel_gpu_ggtt_ranges::Ledger::for_bar(bar.phys.raw(), bar.len)
                .ok(),
            tlb: crate::intel_gpu_ggtt_tlb::Tracker::new(),
        }
    }

    /// GT0's GuC owns this arena's GGTT: xe_ggtt_invalidate always reaches
    /// the primary GT, by MMIO until its submission is enabled.
    fn gt0_guc_client(&mut self) {
        let released = self.tlb.set_mode(
            crate::intel_gpu_ggtt_tlb::GuCTlb::Primary,
            crate::intel_gpu_ggtt_tlb::Mode::Mmio,
        );
        debug_assert!(released.is_empty());
    }

    pub(crate) fn for_gt(
        bar: narf_bus::bar::MmioRegion,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        platform: crate::intel_gpu_gt::GtPlatform,
    ) -> Self {
        let mut arena = Self::new(bar);
        arena.authority = Some(crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap));
        arena.gt_platform = Some(platform);
        arena.gt0_guc_client();
        arena
    }

    /// An SR-IOV-capable PF with no enabled/inherited VFs. Every PTE write
    /// retains the same per-access PCI identity/BAR/D0/VF proof as the GT
    /// register window; no VF lifecycle is implemented here.
    pub(crate) fn for_sriov_pf_gt(
        bar: narf_bus::bar::MmioRegion,
        mmio: crate::intel_gpu_gt_hw::AuthorizedWindow,
        platform: crate::intel_gpu_gt::GtPlatform,
    ) -> Result<Self, SubmitError> {
        if !platform.has_sriov() || !mmio.current() {
            return Err(SubmitError::NoEngine);
        }
        let mut arena = Self::new(bar);
        arena.authority = Some(mmio);
        arena.gt_platform = Some(platform);
        arena.gt0_guc_client();
        Ok(arena)
    }

    pub(crate) fn for_smallbar_gt(
        bar: narf_bus::MmioRegion,
        mmio: crate::intel_gpu_gt_hw::AuthorizedWindow,
        authority: Arc<crate::intel_gpu_gt::smallbar::Authority>,
    ) -> Result<Self, SubmitError> {
        if !authority.matches_window(&mmio, bar) {
            return Err(SubmitError::NoEngine);
        }
        authority
            .current(&mmio)
            .map_err(|_| SubmitError::NoEngine)?;
        let mut arena = Self::new(bar);
        arena.authority = Some(mmio);
        arena.gt_platform = Some(crate::intel_gpu_gt::GtPlatform::Battlemage);
        arena.bmg_authority = Some(authority);
        arena.gt0_guc_client();
        Ok(arena)
    }

    pub(crate) fn for_lnl_gt(
        bar: narf_bus::bar::MmioRegion,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        device: narf_bus::BusDevice,
        receipt: crate::intel_gpu_gt::lnl::Receipt,
    ) -> Result<Self, SubmitError> {
        let platform =
            crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
                .filter(|p| p.is_headless_integrated())
                .ok_or(SubmitError::NoEngine)?;
        let mut arena = Self::for_gt(bar, cap, platform);
        arena.authority = Some(crate::intel_gpu_gt_hw::AuthorizedWindow::for_device(
            bar, cap, device,
        ));
        arena.lnl_device = Some(device);
        arena.lnl_receipt = Some(receipt);
        if !arena.lnl_takeover_ready() {
            return Err(SubmitError::NoEngine);
        }
        Ok(arena)
    }

    fn lnl_takeover_ready(&self) -> bool {
        !self.retired
            && self.authority.as_ref().is_some_and(|mmio| {
                self.lnl_receipt.as_ref().is_some_and(|r| {
                    self.lnl_device
                        .is_some_and(|device| r.matches(device, self.bar, mmio))
                })
            })
    }

    /// Write one GGTT PTE (or zero to invalidate) at `ggtt_off`.
    fn write_pte(&self, ggtt_off: u32, pte: u64) -> Result<(), SubmitError> {
        if self.retired {
            return Err(SubmitError::NoEngine);
        }
        let lnl = self.gt_platform.is_some_and(|p| p.is_headless_integrated());
        if lnl && !self.lnl_takeover_ready() {
            return Err(SubmitError::NoEngine);
        }
        let pte_byte = GGTT_ARRAY_BASE + (ggtt_off as u64 / GTT_PAGE_SIZE) * 8;
        if let Some(window) = &self.authority {
            if let Some(authority) = &self.bmg_authority {
                authority
                    .current(window)
                    .map_err(|_| SubmitError::NoEngine)?;
            }
            let media = if lnl {
                Some(
                    self.policy
                        .and_then(|p| p.media)
                        .ok_or(SubmitError::NoEngine)?,
                )
            } else {
                None
            };
            if let Some(proof) = media {
                proof.current(window).map_err(|_| SubmitError::NoEngine)?;
            }
            window.write32(pte_byte, pte as u32);
            window.write32(pte_byte + 4, (pte >> 32) as u32);
            // Wa_22019338487: RO GMD_ID write drains G-unit PTE writes.
            // Every BMG PTE is conservative relative to the 1100-PTE limit.
            if self.gt_platform == Some(crate::intel_gpu_gt::GtPlatform::Battlemage) {
                window.write32(0xd8c, 0);
            }
            if let Some(proof) = media {
                proof
                    .after_pte(window, &self.lnl_pte_count)
                    .map_err(|_| SubmitError::NoEngine)?;
            }
            return Ok(());
        }
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
        Ok(())
    }

    /// xe_ggtt.c::xe_ggtt_map_bo for the MTL/Arrow media GT's GSC private
    /// object (XE_BO_FLAG_STOLEN | XE_BO_FLAG_GGTT): one DM PTE per page,
    /// `encode_ggtt_stolen(stolen_base + DSM offset, WB index)`, at the
    /// ledger's fixed GSC window above this arena. Without
    /// XE_BO_FLAG_GGTT_INVALIDATE Linux invalidates no TLB on that insert, and
    /// no GuC ever touches the object. The window and its DSM pages are the
    /// function's for its lifetime: the arena never allocates, clears or
    /// retires them, and each GT0 incarnation rewrites the same entries. Every
    /// entry is read back.
    fn map_gsc_stolen(&self, dsm_offset: u64, pages: u32) -> Result<u32, SubmitError> {
        let platform = self.gt_platform.ok_or(SubmitError::NoEngine)?;
        let policy = self.policy.ok_or(SubmitError::NoEngine)?;
        let window = crate::intel_gpu_stolen::GSC_GGTT;
        let bytes = u64::from(pages) * GTT_PAGE_SIZE;
        if !crate::intel_gpu_gt::media::profile_eligible(platform)
            || policy.platform() != platform
            || self.authority.is_none()
            || bytes != crate::intel_gpu_stolen::GSC_BYTES
            || dsm_offset % GTT_PAGE_SIZE != 0
            || !self.ggtt_ledger.as_ref().is_some_and(|ledger| {
                ledger.allows(crate::intel_gpu_ggtt_ranges::Kind::Gsc, window, bytes)
            })
            || (self.ggtt_va_size != 0 && window + bytes > self.ggtt_va_size)
        {
            return Err(SubmitError::NoEngine);
        }
        let format = platform.pte_format();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(pages as usize)
            .map_err(|_| SubmitError::OutOfMemory)?;
        for page in 0..u64::from(pages) {
            let gsm = crate::intel_gpu_stolen::DSM_GSM_OFFSET + dsm_offset + page * GTT_PAGE_SIZE;
            entries.push(
                format
                    .encode_ggtt_stolen(gsm, policy.ggtt_pat())
                    .map_err(|_| SubmitError::OutOfMemory)?,
            );
        }
        for (page, pte) in entries.iter().enumerate() {
            self.write_pte(window as u32 + page as u32 * GTT_PAGE_SIZE as u32, *pte)?;
        }
        compiler_fence(Ordering::SeqCst);
        let mmio = self.authority.as_ref().ok_or(SubmitError::NoEngine)?;
        for (page, pte) in entries.iter().enumerate() {
            let slot = GGTT_ARRAY_BASE + (window / GTT_PAGE_SIZE + page as u64) * 8;
            let read = u64::from(mmio.read32(slot)) | u64::from(mmio.read32(slot + 4)) << 32;
            if read != *pte {
                return Err(SubmitError::NoEngine);
            }
        }
        compiler_fence(Ordering::SeqCst);
        Ok(window as u32)
    }

    /// Posting flush for a burst of arena PTE writes: fence,
    /// then read back the slot at `last_ggtt_off` so the writes
    /// are visible before the backing is handed to an engine.
    /// Then xe_ggtt.c::xe_ggtt_invalidate: the VF_CAP_REG barrier, then
    /// each GuC's GGTT TLB. MMIO-mode GuCs are invalidated here (GT0 through
    /// its own registers, GT1 at the media GSI offset), under the GT wakes
    /// their owners retain. CT-mode GuCs see a new pending generation that
    /// their scheduler invalidates from its poll.
    fn flush_pte_writes(&mut self, last_ggtt_off: u32) {
        use crate::intel_gpu_ggtt_tlb as tlb;
        compiler_fence(Ordering::SeqCst);
        let pte_byte = GGTT_ARRAY_BASE + (last_ggtt_off as u64 / GTT_PAGE_SIZE) * 8;
        let mmio = self.tlb.publish();
        if let Some(window) = &self.authority {
            let _ = window.read32(pte_byte);
            tlb::barrier(window);
            let xe2 = self
                .gt_platform
                .is_some_and(crate::intel_gpu_gt::GtPlatform::is_xe2);
            for (gt, invalidate) in tlb::GuCTlb::ALL.into_iter().zip(mmio) {
                match (invalidate, gt) {
                    (false, _) => {}
                    (true, tlb::GuCTlb::Primary) => tlb::invalidate_mmio(window, xe2),
                    (true, tlb::GuCTlb::Media) => tlb::invalidate_mmio(
                        &crate::intel_gpu_gt::media::MediaWindow::new(window),
                        xe2,
                    ),
                }
            }
            compiler_fence(Ordering::SeqCst);
            return;
        }
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
        if self.retired {
            return Err(SubmitError::NoEngine);
        }
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
        if self.bar.len != 0
            && !self.ggtt_ledger.as_ref().is_some_and(|ledger| {
                ledger.allows(
                    crate::intel_gpu_ggtt_ranges::Kind::Gt,
                    u64::from(off),
                    u64::from(pages) * GTT_PAGE_SIZE,
                )
            })
        {
            return Err(SubmitError::OutOfMemory);
        }
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
        if frames
            .iter()
            .any(|f| self.encode_pte(f.start_address().raw()).is_err())
        {
            for frame in frames {
                narf_memory::frame::free_frame(frame);
            }
            return Err(SubmitError::OutOfMemory);
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
            coherent: self.policy.is_some() && cfg!(target_arch = "x86_64"),
            mapped: self.authority.is_none() || self.policy.is_some(),
        };
        self.live_ranges.insert(off, pages);
        self.live += 1;
        self.live_pages += pages;
        if backing.mapped {
            let mut failed = false;
            for (p, frame) in backing.frames.iter().enumerate() {
                let pte = self
                    .encode_pte(frame.start_address().raw())
                    .expect("validated frame extent");
                if self
                    .write_pte(off + (p as u32) * GTT_PAGE_SIZE as u32, pte)
                    .is_err()
                {
                    // A partially published allocation remains retained and its
                    // range reserved. Authority loss is not DMA retirement.
                    failed = true;
                    break;
                }
            }
            if failed {
                core::mem::forget(backing);
                return Err(SubmitError::NoEngine);
            }
            self.flush_pte_writes(off + (pages - 1) * GTT_PAGE_SIZE as u32);
        }
        backing.zero_fill();
        Ok(backing)
    }

    /// xe_ggtt.c::ggtt_node_remove: clear the PTEs, then invalidate every
    /// GuC TLB before the backing is freed. A CT-mode GuC cannot complete that
    /// here, so the range and its frames stay out of the free list until its
    /// scheduler observes the covering TLB_INVALIDATION_DONE, or until that
    /// GuC's reset is proven. A range that never had live PTEs has nothing to
    /// invalidate. After whole-arena retirement the reset already covers it.
    fn free(&mut self, backing: FrameBacking) {
        let published = backing.mapped && !self.retired;
        if published {
            let cleared = self.cleared_pte();
            for p in 0..backing.pages {
                if self
                    .write_pte(backing.ggtt + p * GTT_PAGE_SIZE as u32, cleared)
                    .is_err()
                {
                    core::mem::forget(backing);
                    return;
                }
            }
            self.flush_pte_writes(backing.ggtt + (backing.pages - 1) * GTT_PAGE_SIZE as u32);
        }
        let range = RetainedRange {
            ggtt: backing.ggtt,
            pages: backing.pages,
            frames: backing.frames,
        };
        if !published {
            self.release(range);
            return;
        }
        let generation = self.tlb.generation();
        if let Some(range) = self.tlb.remove(generation, range) {
            self.release(range);
        }
    }

    fn live_allocations(&self) -> usize {
        self.live
    }
    fn live_pages(&self) -> u32 {
        self.live_pages
    }
}

/// Physical address of the zeroed frame behind every cleared GGTT PTE, or 0
/// before the first clear. PTEs naming it outlive any one arena (a GT reset
/// does not rewrite the GGTT), so the frame is never returned.
static GGTT_SCRATCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn ggtt_scratch() -> Option<u64> {
    let phys = GGTT_SCRATCH.load(Ordering::Acquire);
    if phys != 0 {
        return Some(phys);
    }
    let frame = narf_memory::frame::alloc_frame().ok()?;
    // SAFETY: a frame this call owns, reached through its direct-map page.
    unsafe {
        core::ptr::write_bytes(
            frame.start_address().kernel_mut_ptr::<u8>(),
            0,
            GTT_PAGE_SIZE as usize,
        );
    }
    let raw = frame.start_address().raw();
    match GGTT_SCRATCH.compare_exchange(0, raw, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(raw),
        Err(winner) => {
            narf_memory::frame::free_frame(frame);
            Some(winner)
        }
    }
}

impl GgttArena {
    /// xe_ggtt.c::xe_ggtt_clear: a cleared PTE maps the zeroed scratch page,
    /// never an invalid entry. An engine can still touch a context's GGTT
    /// range after GuC deregistered it (the idle, still-resident context is
    /// saved, or its WA batch fetched, on the next switch); scratch absorbs
    /// that access where an invalid PTE raises NOTIFY_MEMORY_CAT_ERROR and
    /// loses the GT. Without a scratch frame the clear falls back to 0.
    pub(crate) fn cleared_pte(&self) -> u64 {
        ggtt_scratch()
            .and_then(|phys| self.encode_pte(phys).ok())
            .unwrap_or(0)
    }

    /// Return a range whose clear every GuC has invalidated: its frames to
    /// the frame allocator and its GGTT pages to the free list.
    fn release(&mut self, range: RetainedRange) {
        for f in range.frames {
            narf_memory::frame::free_frame(f);
        }
        self.live -= 1;
        self.live_pages -= range.pages;
        self.live_ranges.remove(&range.ggtt);
        // Reinsert and coalesce with neighbours.
        self.free_list.push((range.ggtt, range.pages));
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

    /// Apply one GuC-TLB bookkeeping step and release what it made safe.
    fn guc_tlb_step(&mut self, step: impl FnOnce(&mut GuCTlbTracker) -> Vec<RetainedRange>) {
        for range in step(&mut self.tlb) {
            self.release(range);
        }
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

    pub(crate) fn lnl_takeover_ready(&self) -> bool {
        self.inner.lock().lnl_takeover_ready()
    }

    /// Register (`true`) the MTL/Arrow media GuC as a second GGTT TLB of this
    /// arena before its firmware can translate, or unregister it after its
    /// verified stop. Unregistering releases ranges held only for GT1.
    /// Only an authorized MTL-classified arena qualifies. GT0's own GuC TLB
    /// is invalidated on every update either way.
    pub(crate) fn set_media_guc_tlb(&self, live: bool) -> Result<(), SubmitError> {
        use crate::intel_gpu_ggtt_tlb::{GuCTlb, Mode};
        let mut arena = self.inner.lock();
        if arena.retired
            || arena.authority.is_none()
            || !arena
                .gt_platform
                .is_some_and(crate::intel_gpu_gt::media::profile_eligible)
        {
            return Err(SubmitError::NoEngine);
        }
        let mode = if live { Mode::Mmio } else { Mode::Off };
        arena.guc_tlb_step(|tlb| tlb.set_mode(GuCTlb::Media, mode));
        Ok(())
    }

    /// Switch the registered media GuC between MMIO (`false`) and CT (`true`)
    /// GGTT invalidation. Equivalent to `set_guc_tlb_ct(GuCTlb::Media, ..)`.
    pub(crate) fn set_media_guc_submission(&self, enabled: bool) -> Result<(), SubmitError> {
        self.set_guc_tlb_ct(crate::intel_gpu_ggtt_tlb::GuCTlb::Media, enabled)
    }

    /// Select a registered GuC's GGTT invalidation: MMIO GUC_TLB_INV_CR /
    /// PVC_GUC_TLB_INV_DESC (`false`) or its CT TLB_INVALIDATION (`true`).
    /// This follows send_tlb_inval_ggtt's
    /// `xe_guc_ct_enabled && submission_state.enabled` test. Leaving CT keeps
    /// any range still owed a CT invalidation until that GuC's reset is proven.
    pub(crate) fn set_guc_tlb_ct(
        &self,
        gt: crate::intel_gpu_ggtt_tlb::GuCTlb,
        enabled: bool,
    ) -> Result<(), SubmitError> {
        use crate::intel_gpu_ggtt_tlb::Mode;
        let mut arena = self.inner.lock();
        if arena.retired || arena.authority.is_none() || arena.tlb.mode(gt) == Mode::Off {
            return Err(SubmitError::NoEngine);
        }
        let mode = if enabled { Mode::Ct } else { Mode::Mmio };
        arena.guc_tlb_step(|tlb| tlb.set_mode(gt, mode));
        Ok(())
    }

    /// The generation a CT-mode GuC must still invalidate, if any. The
    /// scheduler sends the TLB_INVALIDATION after this returns, with no
    /// arena lock held.
    pub(crate) fn guc_tlb_pending(&self, gt: crate::intel_gpu_ggtt_tlb::GuCTlb) -> Option<u64> {
        self.inner.lock().tlb.pending(gt)
    }

    /// TLB_INVALIDATION_DONE for a request issued at `generation`: release
    /// every retained range all GuCs have now invalidated.
    pub(crate) fn guc_tlb_complete(&self, gt: crate::intel_gpu_ggtt_tlb::GuCTlb, generation: u64) {
        self.inner
            .lock()
            .guc_tlb_step(|tlb| tlb.complete(gt, generation));
    }

    /// The GuC's reset (or a full GT reset) was proven.
    /// xe_tlb_inval_reset releases what was waiting on it.
    pub(crate) fn guc_tlb_reset(&self, gt: crate::intel_gpu_ggtt_tlb::GuCTlb) {
        self.inner.lock().guc_tlb_step(|tlb| tlb.reset(gt));
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn guc_tlb_mode(
        &self,
        gt: crate::intel_gpu_ggtt_tlb::GuCTlb,
    ) -> crate::intel_gpu_ggtt_tlb::Mode {
        self.inner.lock().tlb.mode(gt)
    }

    /// Cleared ranges (GGTT offset, pages) still awaiting an invalidation.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn guc_tlb_retained(&self) -> Vec<(u32, u32)> {
        self.inner
            .lock()
            .tlb
            .retained_items()
            .map(|range| (range.ggtt, range.pages))
            .collect()
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn media_guc_tlb(&self) -> bool {
        self.guc_tlb_mode(crate::intel_gpu_ggtt_tlb::GuCTlb::Media)
            != crate::intel_gpu_ggtt_tlb::Mode::Off
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn media_guc_ct(&self) -> bool {
        self.guc_tlb_mode(crate::intel_gpu_ggtt_tlb::GuCTlb::Media)
            == crate::intel_gpu_ggtt_tlb::Mode::Ct
    }

    /// The PTE `free` writes over a cleared range (see `GgttArena::cleared_pte`).
    #[cfg(feature = "kernel-test")]
    pub(crate) fn cleared_pte(&self) -> u64 {
        self.inner.lock().cleared_pte()
    }

    pub(crate) fn retire_ggtt(&self) -> Result<(), SubmitError> {
        let mut arena = self.inner.lock();
        if !arena
            .gt_platform
            .is_some_and(|p| p.is_headless_integrated())
            || arena.retired
        {
            return Ok(());
        }
        let ranges: Vec<(u32, u32)> = arena
            .live_ranges
            .iter()
            .map(|(&offset, &pages)| (offset, pages))
            .collect();
        for (offset, pages) in ranges {
            for page in 0..pages {
                arena.write_pte(offset + page * 4096, 0)?;
            }
            arena.flush_pte_writes(offset + (pages - 1) * 4096);
        }
        arena.retired = true;
        Ok(())
    }

    /// Map the GSC private object's claimed DSM range at the fixed GSC GGTT
    /// window (`GgttArena::map_gsc_stolen`); returns the window's GGTT base.
    pub(crate) fn map_gsc_stolen(&self, dsm_offset: u64, pages: u32) -> Result<u32, SubmitError> {
        self.inner.lock().map_gsc_stolen(dsm_offset, pages)
    }

    pub(crate) fn configure_cache(
        &self,
        backing: &mut FrameBacking,
        policy: crate::intel_gpu_gt_hw::CachePolicy,
    ) -> Result<(), SubmitError> {
        let mut arena = self.inner.lock();
        if arena
            .gt_platform
            .is_some_and(|platform| platform != policy.platform())
        {
            return Err(SubmitError::NoEngine);
        }
        if arena.policy.is_some_and(|old| {
            old.platform() != policy.platform() || old.ggtt_pat() != policy.ggtt_pat()
        }) {
            return Err(SubmitError::NoEngine);
        }
        if policy.platform().is_headless_integrated()
            && (!arena.lnl_takeover_ready() || policy.media.is_none())
        {
            return Err(SubmitError::NoEngine);
        }
        arena.policy = Some(policy);
        // Retain the backing on every partially published failure path.
        backing.mapped = true;
        for (i, frame) in backing.frames.iter().enumerate() {
            let pte = arena
                .encode_pte(frame.start_address().raw())
                .map_err(|_| SubmitError::OutOfMemory)?;
            arena.write_pte(backing.ggtt + i as u32 * 4096, pte)?;
        }
        arena.flush_pte_writes(backing.ggtt + (backing.pages - 1) * 4096);
        // The hardware policy requests snooped system-memory access. The ARM
        // PCI host-bridge coherency contract is not established by this driver.
        backing.coherent = cfg!(target_arch = "x86_64");
        backing.mapped = true;
        Ok(())
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
/// Hardware render context image size in pages, shared by
/// Gen11 and Gen12 (MIT `intel_engine_cs.c`:
/// `intel_engine_context_size` returns
/// `GEN11_LR_CONTEXT_RENDER_SIZE` — 14 pages — for graphics
/// 11 and 12 alike). The 48-page allocation above bounds it
/// on both generations; no per-generation bound is needed.
pub const RENDER_IMAGE_PAGES: u32 = 14;

/// Hardware render context image size in pages for
/// `generation` (MIT `intel_engine_cs.c`:
/// `intel_engine_context_size` returns
/// `GEN9_LR_CONTEXT_RENDER_SIZE` — 22 pages — for graphics 9
/// and `GEN11_LR_CONTEXT_RENDER_SIZE` — 14 pages — for
/// graphics 11 and 12). The 48-page allocation above bounds
/// the 22-page Gen9 image too, so no allocation change is
/// needed — only the bound the engine reports.
pub const fn render_image_pages(generation: crate::intel_gpu::Generation) -> u32 {
    match generation {
        crate::intel_gpu::Generation::Skylake => 22,
        _ => RENDER_IMAGE_PAGES,
    }
}
/// Hardware non-render (video decode / enhancement / copy /
/// other) context image size in pages, shared by every Gen8+
/// generation (MIT `intel_engine_cs.c`:
/// `GEN8_LR_CONTEXT_OTHER_SIZE` — 2 pages — returned by the
/// non-render branch of `intel_engine_context_size` for every
/// graphics version >= 8, verified for Gen9 in this lane).
/// The media allocation bound (`MEDIA_IMAGE_PAGES` = 4) covers
/// it.
pub const OTHER_IMAGE_PAGES: u32 = 2;
const _: () = assert!(RCS_IMAGE_PAGES >= RENDER_IMAGE_PAGES);
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
    let need = u32::try_from(dwords.len())
        .ok()
        .and_then(|n| n.checked_mul(4))
        .ok_or(SubmitError::RingFull)?;
    let used = ring.tail.wrapping_sub(ring.head) & (RING_BYTES - 1);
    let padding = if need > RING_BYTES - ring.tail {
        RING_BYTES - ring.tail
    } else {
        0
    };
    if need
        .checked_add(padding)
        .is_none_or(|total| total > RING_BYTES.saturating_sub(used).saturating_sub(8))
    {
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
    /// raw attachment's caller owns its tables; `submit_resident` instead
    /// retains their owner in the request through verified retirement.
    ppgtt_root: Option<u64>,
    /// The image holds hardware-saved engine state. Gen9/Gen11 contexts
    /// start with restore inhibited (Linux `init_common_regs` with no
    /// default image) and clear it once their first request retires.
    restore_valid: bool,
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
    batch: RequestBatch<A>,
    fence: Arc<CompletionFence>,
}

// Retain the residency graph inline: boxing it adds a fallible allocation to
// admission and complicates the manual quarantine lifetime for uncertain DMA.
#[allow(clippy::large_enum_variant)]
enum RequestBatch<A: GpuAllocator> {
    Ggtt(BatchBuf<A>),
    // Dropping an engine is not proof that DMA stopped. Deliberately retain
    // the full address space on unconfirmed teardown, including preempted
    // requests that were returned to the software queue.
    Resident(ManuallyDrop<ResidentBatch>),
}

impl<A: GpuAllocator> RequestBatch<A> {
    fn address(&self) -> u64 {
        match self {
            Self::Ggtt(batch) => batch.ggtt_offset() as u64,
            Self::Resident(batch) => batch.address(),
        }
    }
    fn release(self, alloc: &mut A) {
        match self {
            Self::Ggtt(batch) => alloc.free(batch.backing),
            Self::Resident(batch) => drop(ManuallyDrop::into_inner(batch)),
        }
    }
}

#[derive(Debug)]
pub struct ResidentSubmission {
    pub request: u64,
    pub fence: Arc<CompletionFence>,
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
    /// Generation selecting the context-image template
    /// ([`build_reg_state_for_generation`]): Gen9 takes its
    /// own layout, Gen11 takes its own layout, everything else
    /// the Gen12-shaped one.
    generation: crate::intel_gpu::Generation,
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
    next_sw_id: u16,
    completion_lost: bool,
    /// Gen9's engine-wide indirect-context workaround batch and the GT
    /// scratch page it saves `GEN8_L3SQCREG4` into ([`Self::install_gen9_wa_bb`]).
    wa_bb: Option<(A::Backing, A::Backing, u32)>,
    /// Linux `engine->default_state`: the image the hardware saved for a
    /// context that ran the context workarounds and, on Gen9, the null
    /// render state ([`Self::begin_default_image`]). Later contexts start
    /// from it instead of restore-inhibited.
    default_image: Option<A::Backing>,
    /// `HAS_POOLED_EU` (a Gen9 LP part with all three subslices): the
    /// media pool state joins the indirect-context batch and the golden
    /// render state ([`Self::set_pooled_eu`]).
    pooled_eu: bool,
    /// When ELSP[0]'s current slice began ([`Self::timeslice`]).
    slice_start: Option<u64>,
    /// A timeslice ELSP is outstanding: every ring is paused at its
    /// breadcrumb and the switched-out contexts' requests are queued again.
    preempting: bool,
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

    /// Bring up the RCS0 engine for the generation
    /// `generation` (Gen9/Gen11 take their own context-image
    /// templates; see [`build_reg_state_for_generation`]).
    pub fn new_for_generation(
        generation: crate::intel_gpu::Generation,
        mmio: M,
        alloc: A,
    ) -> Result<Self, SubmitError> {
        Self::with_spec_for_generation(RCS0_SPEC, generation, mmio, alloc)
    }

    /// Bring up the engine `spec` names: allocate the engine
    /// status page and program that engine's `RING_HWS_PGA`,
    /// then adopt the hardware's current CSB write pointer so
    /// no stale entry is replayed.
    pub fn with_spec(spec: EngineSpec, mmio: M, alloc: A) -> Result<Self, SubmitError> {
        Self::with_spec_for_generation(spec, crate::intel_gpu::Generation::TigerLake, mmio, alloc)
    }

    /// Bring up the engine `spec` names for the generation
    /// `generation`: allocate the engine status page and program
    /// that engine's `RING_HWS_PGA`, then adopt the hardware's
    /// current CSB write pointer so no stale entry is replayed.
    pub fn with_spec_for_generation(
        spec: EngineSpec,
        generation: crate::intel_gpu::Generation,
        mmio: M,
        mut alloc: A,
    ) -> Result<Self, SubmitError> {
        let status = alloc.alloc(1)?;
        mmio.write32(spec.hws_pga(), status.ggtt_offset());
        let head =
            ((status.read32(csb_write_byte(generation)) & 0xFF) as u8) % csb_entries(generation);
        Ok(Self {
            spec,
            generation,
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
            next_sw_id: 1,
            completion_lost: false,
            wa_bb: None,
            default_image: None,
            pooled_eu: false,
            slice_start: None,
            preempting: false,
        })
    }

    /// `lrc_init_wa_ctx` for Gen9 RCS: build [`gen9_init_indirectctx_bb`]
    /// once per engine in a GGTT page, against a GT scratch page (the
    /// coherent-L3 save dword at scratch + 256), and point every context
    /// created afterwards at it ([`setup_gen9_indirect_ctx`]). A pooled-EU
    /// part adds `WaMediaPoolStateCmdInWABB` ([`Self::set_pooled_eu`]).
    /// Other generations and engines take no batch.
    pub fn install_gen9_wa_bb(&mut self) -> Result<(), SubmitError> {
        if !matches!(self.generation, crate::intel_gpu::Generation::Skylake)
            || self.spec.class != EngineClass::Render
            || self.wa_bb.is_some()
        {
            return Ok(());
        }
        let scratch = self.alloc.alloc(1)?;
        let bb = match self.alloc.alloc(1) {
            Ok(bb) => bb,
            Err(error) => {
                self.alloc.free(scratch);
                return Err(error);
            }
        };
        let mut words = [MI_NOOP; GEN9_INDIRECT_CTX_BB_DWORDS];
        let n = gen9_init_indirectctx_bb(&mut words, self.pooled_eu, scratch.ggtt_offset() + 256);
        for (i, word) in words[..n].iter().enumerate() {
            bb.write32(i as u64 * 4, *word);
        }
        self.wa_bb = Some((scratch, bb, n as u32 * 4));
        Ok(())
    }

    /// `reset_csb_pointers`: after an engine reset the hardware writes CSB
    /// entry 0 next, so the read head and the status page's write pointer
    /// both point at the last entry, every entry is marked unwritten
    /// (all-ones), and `RING_CONTEXT_STATUS_PTR` is forced to match ("Ice
    /// Lake forgets to reset its pointers on a GPU reset"). Only valid with
    /// nothing loaded on the engine.
    /// `HAS_POOLED_EU`, from the GT's subslice fuses: set before
    /// [`Self::install_gen9_wa_bb`] and [`Self::begin_default_image`].
    pub fn set_pooled_eu(&mut self, pooled: bool) {
        self.pooled_eu = pooled;
    }

    pub fn reset_csb_pointers(&mut self) -> Result<(), SubmitError> {
        if !self.is_idle() {
            return Err(SubmitError::ContextBusy);
        }
        let entries = csb_entries(self.generation);
        let reset = u32::from(entries - 1);
        let ptr = self.spec.context_status_ptr();
        self.mmio.write32(ptr, 0xffff << 16 | reset << 8 | reset);
        let _ = self.mmio.read32(ptr);
        self.csb_head = entries - 1;
        self.status.write32(csb_write_byte(self.generation), reset);
        // No timeslice survives a reset: every ring runs unpaused.
        self.status.write32(HWS_PREEMPT_BYTE, 0);
        self.preempting = false;
        self.slice_start = None;
        for i in 0..u64::from(entries) {
            self.status.write32(CSB_BUF_BYTE + i * 8, u32::MAX);
            self.status.write32(CSB_BUF_BYTE + i * 8 + 4, u32::MAX);
        }
        fence(Ordering::Release);
        self.mmio.write32(ptr, 0xffff << 16 | reset << 8 | reset);
        let _ = self.mmio.read32(ptr);
        Ok(())
    }

    /// `execlists_reset_rewind` after the caller reset this engine alone
    /// (`intel_engine_reset`). The context on port 0 hung: every request of
    /// it, in flight or queued, fails with [`JobError::Hang`] and its batches
    /// are released. Other contexts resume from their saved images (a
    /// timeslice may have switched one out): their requests go back to the queue in order,
    /// with their images untouched. The status page address and the CSB
    /// pointers are restored (the reset clears both) and the queue is pumped.
    /// Returns the hung context and the failed request ids.
    ///
    /// # Safety
    /// The caller completed a reset of this engine, so the hardware no
    /// longer references any of its batch, ring or context memory.
    pub unsafe fn reset_rewind(&mut self) -> Result<(Option<ContextId>, Vec<u64>), SubmitError> {
        // SAFETY: the caller's contract is this function's.
        unsafe { self.reset_rewind_blaming(None) }
    }

    /// [`Self::reset_rewind`] with the overdue `request` named: its context
    /// is the guilty one even when a timeslice switched it out of ELSP[0]
    /// (Linux cancels the expired request, wherever it is). Unknown or
    /// already retired, ELSP[0]'s context is blamed.
    ///
    /// # Safety
    /// As [`Self::reset_rewind`].
    pub unsafe fn reset_rewind_blaming(
        &mut self,
        request: Option<u64>,
    ) -> Result<(Option<ContextId>, Vec<u64>), SubmitError> {
        if self.completion_lost {
            return Err(SubmitError::CompletionLost);
        }
        let named = request.and_then(|id| {
            self.inflight
                .iter()
                .chain(self.queue.iter())
                .find(|r| r.id == id)
                .map(|r| r.ctx_slot)
        });
        let guilty = named.or(self.active[0]).or(self.pending[0]);
        let guilty_id = guilty.and_then(|slot| {
            self.contexts
                .get(slot as usize)
                .and_then(Option::as_ref)
                .map(|ctx| ContextId::pack(ctx.slot, ctx.generation))
        });
        self.active = [None, None];
        self.pending = [None, None];
        let mut failed = Vec::new();
        let mut requeue = VecDeque::new();
        let older: Vec<_> = self.inflight.drain(..).collect();
        for request in older.into_iter().chain(self.queue.drain(..)) {
            if Some(request.ctx_slot) == guilty {
                failed.push(request);
            } else {
                requeue.push_back(request);
            }
        }
        fence(Ordering::Acquire);
        let mut ids = Vec::with_capacity(failed.len());
        for request in failed {
            ids.push(request.id);
            request.batch.release(&mut self.alloc);
            request.fence.signal(Err(JobError::Hang));
        }
        self.mmio
            .write32(self.spec.hws_pga(), self.status.ggtt_offset());
        self.reset_csb_pointers()?;
        self.queue = requeue;
        self.pump();
        Ok((guilty_id, ids))
    }

    /// Append `words` to an idle, unqueued context's ring ahead of its
    /// next request: the per-context setup Linux records into the default
    /// context image (the context workaround `MI_LOAD_REGISTER_IMM`). The
    /// next submission's tail covers them. `words` must be an even count.
    pub fn emit_context_setup(&mut self, id: ContextId, words: &[u32]) -> Result<(), SubmitError> {
        let slot = self.context(id)?.slot;
        if self.ctx_covered(slot) || self.queue.iter().any(|r| r.ctx_slot == slot) {
            return Err(SubmitError::ContextBusy);
        }
        if words.len() % 2 != 0 {
            return Err(SubmitError::RingFull);
        }
        let ctx = self.context_mut(id)?;
        ring_emit(&ctx.ring_mem, &mut ctx.ring, words)
    }

    /// `__engines_record_defaults`, first half: on a fresh restore-inhibited
    /// Gen9/Gen11 render context, run `setup` (the context workaround LRI)
    /// and then the golden batch: Gen9's null render state
    /// ([`crate::intel_gpu_renderstate::gen9_null_state`]), an empty batch on
    /// Gen11, which Linux gives no render state. Returns the context and the
    /// request to wait for; [`Self::finish_default_image`] records the image
    /// once it retires.
    pub fn begin_default_image(&mut self, setup: &[u32]) -> Result<(ContextId, u64), SubmitError> {
        if !gen8_csb(self.generation)
            || self.spec.class != EngineClass::Render
            || self.default_image.is_some()
        {
            return Err(SubmitError::NoEngine);
        }
        let id = self.create_context()?;
        let batch = self.emit_context_setup(id, setup).and_then(|()| {
            let backing = self.alloc.alloc(1)?;
            let words = if matches!(self.generation, crate::intel_gpu::Generation::Skylake) {
                crate::intel_gpu_renderstate::gen9_null_state(
                    u64::from(backing.ggtt_offset()),
                    self.pooled_eu,
                )
            } else {
                crate::intel_gpu_renderstate::empty_state()
            };
            for (i, word) in words.iter().enumerate() {
                backing.write32(i as u64 * 4, *word);
            }
            Ok(BatchBuf {
                backing,
                dwords: words.len() as u32,
            })
        });
        match batch.and_then(|batch| self.submit(id, batch)) {
            Ok(request) => Ok((id, request)),
            Err(error) => {
                let _ = self.destroy_context(id);
                Err(error)
            }
        }
    }

    /// `__engines_record_defaults`, second half: once the golden request
    /// on `id` retired (the hardware saved its image when it switched the
    /// context out), copy the image as the engine default and destroy the
    /// context.
    pub fn finish_default_image(&mut self, id: ContextId) -> Result<(), SubmitError> {
        let ctx = self.context(id)?;
        if self.default_image.is_some() {
            return Err(SubmitError::NoEngine);
        }
        if !ctx.restore_valid
            || ctx.last_completed_seqno == 0
            || self.ctx_covered(ctx.slot)
            || self.queue.iter().any(|r| r.ctx_slot == ctx.slot)
        {
            return Err(SubmitError::ContextBusy);
        }
        let pages = ctx.image.size_pages();
        let copy = self.alloc.alloc(pages)?;
        let ctx = self.context(id)?;
        for offset in (0..u64::from(pages) * GTT_PAGE_SIZE).step_by(4) {
            copy.write32(offset, ctx.image.read32(offset));
        }
        if let Err(error) = self.destroy_context(id) {
            self.alloc.free(copy);
            return Err(error);
        }
        self.default_image = Some(copy);
        Ok(())
    }

    /// Whether later contexts start from a recorded default image.
    pub fn has_default_image(&self) -> bool {
        self.default_image.is_some()
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
        if self.completion_lost {
            return Err(SubmitError::CompletionLost);
        }
        // Never reuse a CSB software identity within an engine lifetime: a
        // delayed event from a destroyed context must not match a new job.
        if self.next_sw_id >= IDLE_SW_ID {
            return Err(SubmitError::TooManyContexts);
        }
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
        let mut template = build_reg_state_for_generation(
            &self.spec,
            ring_mem.ggtt_offset(),
            RING_BYTES,
            self.generation,
        );
        if let Some((_, bb, bytes)) = &self.wa_bb {
            setup_gen9_indirect_ctx(&mut template, bb.ggtt_offset(), *bytes);
        }
        // `lrc_init_state`: with a default image, start from it with the
        // per-context status page cleared, then rewrite the register state.
        // Without one the first load must not restore engine state from an
        // image the hardware never saved.
        if let Some(default) = &self.default_image {
            let pages = default.size_pages().min(image.size_pages());
            for offset in (0..u64::from(pages) * GTT_PAGE_SIZE).step_by(4) {
                let value = if offset < REG_STATE_PAGE_BYTE {
                    0
                } else {
                    default.read32(offset)
                };
                image.write32(offset, value);
            }
        }
        let restore_valid = !gen8_csb(self.generation) || self.default_image.is_some();
        if !restore_valid {
            template[CTX_CONTEXT_CONTROL + 1] |= 1;
        }
        for (i, dw) in template.iter().enumerate() {
            image.write32(REG_STATE_PAGE_BYTE + (i as u64) * 4, *dw);
        }
        let generation = self.generations[slot];
        let sw_id = self.next_sw_id;
        self.next_sw_id += 1;
        let descriptor = context_descriptor_for_generation(
            &self.spec,
            image.ggtt_offset(),
            sw_id,
            self.generation,
        );
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
            restore_valid,
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
        let length = u32::try_from(dwords.len()).map_err(|_| SubmitError::BatchInvalid)?;
        let pages = length.div_ceil(1024);
        let backing = self.alloc.alloc(pages)?;
        for (i, dw) in dwords.iter().enumerate() {
            backing.write32((i as u64) * 4, *dw);
        }
        Ok(BatchBuf {
            backing,
            dwords: length,
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

    /// Submit a batch on a context: emit batch-start, cache drain/stall and
    /// a post-sync breadcrumb into its ring, advance the image
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
        self.submit_inner(id, RequestBatch::Ggtt(batch), false, None)
            .map(|s| s.request)
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
        self.submit_inner(id, RequestBatch::Ggtt(batch), true, None)
            .map(|s| s.request)
    }

    /// Submit an arbitrary PPGTT batch VA with its complete residency owner.
    /// This internal engine API does not publish an untrusted userspace queue.
    /// One resident request per idle context; roots cannot change underneath
    /// queued, pending, active or preempted work. Failed admission releases the
    /// batch immediately; published residency survives fd close and timeout.
    pub fn submit_resident(
        &mut self,
        id: ContextId,
        batch: ResidentBatch,
    ) -> Result<ResidentSubmission, SubmitError> {
        if self.completion_lost {
            return Err(SubmitError::CompletionLost);
        }
        // Gen9/Gen11 PPGTTs use the Gen8 leaf format (prepare_for_gt).
        let format = if gen8_csb(self.generation) {
            crate::intel_gpu_gtt::PteFormat::Gen8
        } else {
            crate::intel_gpu_gtt::PteFormat::Gen12
        };
        // Gen12 resident jobs run on RCS0 here (GuC owns the rest); Gen9 and
        // Gen11 run every execlists engine this way.
        if batch.format() != format
            || (self.spec.class != EngineClass::Render && !gen8_csb(self.generation))
        {
            return Err(SubmitError::NoEngine);
        }
        let ctx = self.context(id)?;
        let slot = ctx.slot;
        let previous = ctx.ppgtt_root;
        if self.ctx_covered(slot) || self.queue.iter().any(|r| r.ctx_slot == slot) {
            return Err(SubmitError::ContextBusy);
        }
        let completion = Arc::new(CompletionFence::new());
        batch
            .reserve(&completion)
            .map_err(|_| SubmitError::ContextBusy)?;
        let ready = if !batch.publish_for_device() {
            Err(SubmitError::CacheUnavailable)
        } else {
            self.attach_ppgtt(id, batch.space().root_phys())
        };
        if let Err(error) = ready {
            drop(batch);
            completion.signal(Err(JobError::Reset));
            return Err(error);
        }
        let result = self.submit_inner(
            id,
            RequestBatch::Resident(ManuallyDrop::new(batch)),
            true,
            Some(completion.clone()),
        );
        if result.is_err() {
            let ctx = self.context_mut(id)?;
            Self::patch_pdp_values(&ctx.image, previous);
            ctx.ppgtt_root = previous;
            completion.signal(Err(JobError::Reset));
        }
        result
    }

    fn submit_inner(
        &mut self,
        id: ContextId,
        batch: RequestBatch<A>,
        ppgtt_form: bool,
        completion: Option<Arc<CompletionFence>>,
    ) -> Result<ResidentSubmission, SubmitError> {
        if self.completion_lost {
            batch.release(&mut self.alloc);
            return Err(SubmitError::CompletionLost);
        }
        let (slot, generation) = match self.context(id) {
            Ok(c) => (c.slot, c.generation),
            Err(e) => {
                batch.release(&mut self.alloc);
                return Err(e);
            }
        };
        if self.ctx_covered(slot) {
            batch.release(&mut self.alloc);
            return Err(SubmitError::ContextBusy);
        }
        if self.queue.len() >= MAX_QUEUED_REQUESTS {
            batch.release(&mut self.alloc);
            return Err(SubmitError::QueueFull);
        }
        let request_id = self.next_request_id;
        let render = self.spec.class == EngineClass::Render;
        let video = self.spec.class == EngineClass::VideoDecode;
        let engine_generation = self.generation;
        let preempt = self.status.ggtt_offset() + HWS_PREEMPT_BYTE as u32;
        let seqno = {
            let ctx = self.context_mut(id)?;
            let seqno = ctx.next_seqno;
            let start = if ppgtt_form {
                mi_batch_buffer_start_ppgtt(batch.address())
            } else {
                mi_batch_buffer_start_ggtt(batch.address())
            };
            let address = ctx.hwsp.ggtt_offset() as u64 + HWSP_SEQNO_BYTE;
            let mut prologue = [MI_NOOP; 16];
            prologue[..3].copy_from_slice(&start);
            let legacy = gen8_csb(engine_generation).then(|| {
                if render {
                    legacy_render_request(
                        matches!(engine_generation, crate::intel_gpu::Generation::IceLake),
                        start,
                        address,
                        seqno,
                        preempt,
                    )
                } else {
                    legacy_xcs_request(video, start, address, seqno, preempt)
                }
            });
            let length = if legacy.is_some() {
                0
            } else if render {
                prologue[3..15].copy_from_slice(&render_breadcrumb(address, seqno));
                16
            } else {
                // XCS has no 3D pipeline: MI_FLUSH_DW is its write barrier.
                prologue[3..7].copy_from_slice(&[
                    0x1300_4002,
                    address as u32 | 4,
                    (address >> 32) as u32,
                    seqno,
                ]);
                8
            };
            let words = legacy.as_deref().unwrap_or(&prologue[..length]);
            if let Err(e) = ring_emit(&ctx.ring_mem, &mut ctx.ring, words) {
                // End the mutable borrow of `self` held through
                // `ctx` so `self.alloc` is usable on this error
                // path. `ctx` is a reference, so nothing is (or
                // could be) dropped — consuming the binding is
                // what ends the borrow.
                let _ = ctx;
                batch.release(&mut self.alloc);
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
        let completion = completion.unwrap_or_else(|| Arc::new(CompletionFence::new()));
        self.queue.push_back(Request {
            ctx_slot: slot,
            ctx_gen: generation,
            seqno,
            id: request_id,
            batch,
            fence: completion.clone(),
        });
        self.pump();
        Ok(ResidentSubmission {
            request: request_id,
            fence: completion,
        })
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
        if root_phys == 0 || root_phys >> 39 != 0 {
            return Err(SubmitError::InvalidPpgttRoot);
        }
        let slot = self.context(id)?.slot;
        if self.ctx_covered(slot) || self.queue.iter().any(|r| r.ctx_slot == slot) {
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
        if self.ctx_covered(slot) || self.queue.iter().any(|r| r.ctx_slot == slot) {
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
        if self.completion_lost || self.pending.iter().any(|p| p.is_some()) || self.queue.is_empty()
        {
            return;
        }
        // A busy Gen9/Gen11 engine is reloaded only by a timeslice
        // ([`Self::timeslice`]), which pauses the rings first: a load is then
        // never a lite restore of the running context.
        if gen8_csb(self.generation) && self.active.iter().any(|a| a.is_some()) {
            return;
        }
        self.load_ports();
    }

    /// Cover the first two distinct queued contexts and write them to the
    /// ELSP.
    fn load_ports(&mut self) {
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
    /// `ring_set_paused`: while set, every request's breadcrumb busywaits, so
    /// no context completes under a preemption in flight.
    fn set_paused(&mut self, paused: bool) {
        self.status.write32(HWS_PREEMPT_BYTE, u32::from(paused));
        fence(Ordering::SeqCst);
    }

    /// Gen9/Gen11 timeslicing (`timeslice_expired`, `execlists_dequeue`):
    /// once ELSP[0]'s context has run [`TIMESLICE_NS`] while another
    /// context waits, in ELSP[1] or the queue (`needs_timeslice`), pause
    /// the rings, return ELSP[1]'s requests to the queue front and
    /// ELSP[0]'s behind every waiter (`__unwind_incomplete_requests`,
    /// `defer_active`), and load the first two contexts into the busy
    /// engine. The hardware switches at its next arbitration point. The
    /// promotion that follows unpauses; a context that completed before the
    /// switch runs again from its saved head, which is its tail, and retires
    /// then. Returns whether the engine was reloaded. Every context has one
    /// priority, so there is no priority preemption.
    pub fn timeslice(&mut self, now: u64) -> bool {
        if !gen8_csb(self.generation)
            || self.completion_lost
            || self.pending.iter().any(Option::is_some)
        {
            return false;
        }
        // After an element switch the running context is in ELSP[1].
        let (first, second) = {
            let mut running = self.active.iter().flatten().copied();
            (running.next(), running.next())
        };
        let Some(first) = first else {
            self.slice_start = None;
            return false;
        };
        if second.is_none() && self.queue.is_empty() {
            self.slice_start = None;
            return false;
        }
        let start = *self.slice_start.get_or_insert(now);
        if now.saturating_sub(start) < TIMESLICE_NS {
            return false;
        }
        self.set_paused(true);
        let (mut deferred, mut resumed, mut keep) = (Vec::new(), Vec::new(), Vec::new());
        for r in self.inflight.drain(..) {
            if r.ctx_slot == first {
                deferred.push(r);
            } else if Some(r.ctx_slot) == second {
                resumed.push(r);
            } else {
                keep.push(r);
            }
        }
        self.inflight = keep;
        for r in resumed.into_iter().rev() {
            self.queue.push_front(r);
        }
        self.queue.extend(deferred);
        self.preempting = true;
        self.slice_start = None;
        self.load_ports();
        true
    }

    /// The timeslice ELSP was promoted: unpause the rings.
    fn finish_preemption(&mut self) {
        self.slice_start = None;
        if self.preempting {
            self.preempting = false;
            self.set_paused(false);
        }
    }

    fn elsp_write(&mut self, port0: u64, port1: u64) {
        fence(Ordering::Release);
        if uses_submit_queue(self.generation) {
            // execlists_submit_ports: every port written, highest first,
            // low dword then high, then EL_CTRL_LOAD.
            let sq = self.spec.execlist_sq();
            self.mmio.write32(sq + 8, port1 as u32);
            self.mmio.write32(sq + 12, (port1 >> 32) as u32);
            self.mmio.write32(sq, port0 as u32);
            self.mmio.write32(sq + 4, (port0 >> 32) as u32);
            self.mmio.write32(self.spec.execlist_control(), 1);
            let _ = self.mmio.read32(self.spec.execlist_status());
            return;
        }
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
        !self.completion_lost
            && self.queue.is_empty()
            && self.inflight.is_empty()
            && self.pending.iter().all(|p| p.is_none())
            && self.active.iter().all(|a| a.is_none())
    }

    pub fn poll_completions(&mut self) -> Vec<CompletedRequest> {
        let mut done = Vec::new();
        if self.completion_lost {
            return done;
        }
        let entries = csb_entries(self.generation);
        let tail = (self.status.read32(csb_write_byte(self.generation)) & 0xFF) as u8;
        if tail >= entries {
            self.completion_lost = true;
            return done;
        }
        // GPU publishes the cursor after the CSB entries and saved state.
        fence(Ordering::Acquire);
        let consume = gen8_csb(self.generation);
        let mut head = self.csb_head;
        while head != tail {
            let next = (head + 1) % entries;
            let base = CSB_BUF_BYTE + (next as u64) * 8;
            let entry = CsbEntry {
                lower: self.status.read32(base),
                upper: self.status.read32(base + 4),
            };
            if consume {
                // csb_read (icl:HSDES#1806554093): the write pointer can be
                // observed before the entry. An entry still all-ones is not
                // written yet; leave it for the next poll. Each consumed
                // entry is reset so its reuse is visible.
                if entry.lower == u32::MAX && entry.upper == u32::MAX {
                    break;
                }
                self.status.write32(base, u32::MAX);
                self.status.write32(base + 4, u32::MAX);
            }
            head = next;
            self.process_csb(entry, &mut done);
            if self.completion_lost {
                break;
            }
        }
        self.csb_head = head;
        self.pump();
        done
    }

    fn process_csb(&mut self, entry: CsbEntry, done: &mut Vec<CompletedRequest>) {
        let any_active = self.active.iter().any(|a| a.is_some());
        if gen8_csb(self.generation) {
            // Gen8-format entries carry no id this engine relies on: like
            // i915, attribute them to the ports in order.
            let first = self.active.iter().flatten().copied().next();
            match gen8_csb_step(&entry, any_active) {
                CsbStep::Promote => {
                    if self.pending.iter().any(|p| p.is_some()) {
                        self.active = self.pending;
                        self.pending = [None, None];
                        self.finish_preemption();
                    } else {
                        self.spurious_csb += 1;
                    }
                }
                CsbStep::Preempt => {
                    // A timeslice already queued the switched-out contexts'
                    // requests again.
                    if let Some(slot) = first.filter(|_| !self.preempting) {
                        self.unschedule(slot);
                    }
                    self.active = self.pending;
                    self.pending = [None, None];
                    self.finish_preemption();
                }
                CsbStep::Complete => match first {
                    // Completed under a timeslice ELSP: its requests are queued
                    // again and retire when the context next runs.
                    Some(slot) if self.preempting => {
                        if let Some(port) = self.active.iter_mut().find(|a| **a == Some(slot)) {
                            *port = None;
                        }
                    }
                    Some(slot) => {
                        self.retire(slot, done);
                        // The next context starts a slice of its own.
                        self.slice_start = None;
                    }
                    None => {}
                },
                CsbStep::Nop => self.spurious_csb += 1,
            }
            return;
        }
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
        if !self.active.contains(&Some(slot)) {
            self.spurious_csb += 1;
            return;
        }
        let Some(expected) = self.inflight.iter().rev().find(|r| r.ctx_slot == slot) else {
            self.spurious_csb += 1;
            return;
        };
        let ctx = self.contexts[slot as usize]
            .as_ref()
            .expect("inflight context");
        let saved_head = ctx
            .image
            .read32(REG_STATE_PAGE_BYTE + ((CTX_RING_HEAD + 1) as u64) * 4);
        if ctx.generation != expected.ctx_gen
            || ctx.hwsp.read32(HWSP_SEQNO_BYTE) != expected.seqno
            || saved_head & (RING_BYTES - 1) != ctx.ring.tail
        {
            // A context-switch notification alone is not completion proof.
            // Stop publishing and retain everything for a proven reset.
            self.completion_lost = true;
            return;
        }
        fence(Ordering::Acquire);
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
            if !ctx.restore_valid {
                // The hardware has saved this context once: later loads
                // restore it.
                let control = REG_STATE_PAGE_BYTE + ((CTX_CONTEXT_CONTROL + 1) as u64) * 4;
                ctx.image.write32(control, ctx.image.read32(control) & !1);
                ctx.restore_valid = true;
            }
            for r in &batches {
                ctx.last_completed_seqno = r.seqno;
            }
            if batches
                .iter()
                .any(|r| matches!(r.batch, RequestBatch::Resident(_)))
            {
                // This image must not retain a root whose pages are about to
                // be released. Resident admission permits only one idle job.
                Self::patch_pdp_values(&ctx.image, None);
                ctx.ppgtt_root = None;
            }
        }
        for r in batches {
            done.push(CompletedRequest {
                ctx: ContextId::pack(r.ctx_slot, r.ctx_gen),
                seqno: r.seqno,
                request: r.id,
            });
            r.batch.release(&mut self.alloc);
            r.fence.signal(Ok(()));
        }
    }

    pub fn completion_lost(&self) -> bool {
        self.completion_lost
    }

    /// Release all pinned requests with a terminal reset error and reclaim
    /// the engine's allocations. A timeout or an unreadable BAR cannot call
    /// this; dropping the owner without proof retains published residency.
    ///
    /// # Safety
    /// The owning GT must have completed a hardware reset or removal that
    /// prevents every engine/GuC/DMA agent from accessing these allocations,
    /// and must not reuse old descriptors or status-page addresses afterwards.
    pub unsafe fn release_after_reset(mut self) {
        fence(Ordering::Acquire);
        for r in self.queue.drain(..).chain(self.inflight.drain(..)) {
            r.batch.release(&mut self.alloc);
            r.fence.signal(Err(JobError::Reset));
        }
        for ctx in self.contexts.drain(..).flatten() {
            self.alloc.free(ctx.image);
            self.alloc.free(ctx.ring_mem);
            self.alloc.free(ctx.hwsp);
        }
        if let Some((scratch, bb, _)) = self.wa_bb.take() {
            self.alloc.free(bb);
            self.alloc.free(scratch);
        }
        if let Some(default) = self.default_image.take() {
            self.alloc.free(default);
        }
        self.alloc.free(self.status);
    }

    /// Sync bridge for callers outside executor polls, including lock/IRQ
    /// contexts. The async form sleeps between completion samples.
    pub fn wait_seqno(
        &mut self,
        id: ContextId,
        seqno: u32,
        timeout_ns: u64,
    ) -> Result<(), SubmitError> {
        narf_scheduler::block_on_spin(self.wait_seqno_async(id, seqno, timeout_ns))
    }

    /// Timer-driven completion sampling. Cancellation drops only this wait;
    /// pending requests keep all residency until completion or proven reset.
    pub async fn wait_seqno_async(
        &mut self,
        id: ContextId,
        seqno: u32,
        timeout_ns: u64,
    ) -> Result<(), SubmitError> {
        let deadline = narf_time::Deadline::after_ns(timeout_ns);
        loop {
            let _ = self.poll_completions();
            if self.completion_lost {
                return Err(SubmitError::CompletionLost);
            }
            let last = self.last_completed_seqno(id)?;
            if seqno != 0 && (last.wrapping_sub(seqno) as i32) >= 0 && last != 0 {
                return Ok(());
            }
            if deadline.expired() {
                return Err(SubmitError::Timeout);
            }
            let wake = core::cmp::min(
                narf_time::Deadline::after_us(50).as_instant(),
                deadline.as_instant(),
            );
            narf_time::SleepUntil::new(wake).await;
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
#[derive(Clone)]
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

    pub(crate) fn matches_legacy(
        &self,
        lease: &crate::intel_gpu_gt::ownership::LegacyLease,
    ) -> bool {
        lease.matches(self.bar)
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

/// Generations whose execlists submission is admitted without any GuC.
/// GuC submission is optional on Gen9/Gen11 (Linux: execlists works without
/// GuC; GuC is required only for HuC auth and GuC submission), and the
/// Gen12 path here predates the GuC owner the same way. Admission takes
/// only the generation — no GuC profile, image or owner is consulted —
/// so a Gen9 or Gen11 part submits on RCS with no GuC loaded; a GuC claim, if
/// one ever exists for the function, still excludes the legacy path
/// through the ownership registry below.
pub(crate) const fn legacy_submission_generation(generation: crate::intel_gpu::Generation) -> bool {
    matches!(
        generation,
        crate::intel_gpu::Generation::TigerLake
            | crate::intel_gpu::Generation::AlderLake
            | crate::intel_gpu::Generation::IceLake
            | crate::intel_gpu::Generation::Skylake
    )
}

pub(crate) fn legacy_submission_lease(
) -> Result<crate::intel_gpu_gt::ownership::LegacyLease, SubmitError> {
    crate::intel_gpu::with_controller(|gpu| {
        if !legacy_submission_generation(gpu.chip_info().generation) {
            return Err(SubmitError::NoEngine);
        }
        // Capture identity and reserve while the same controller guard is
        // held. A GuC claim can never overtake legacy allocation or MMIO.
        crate::intel_gpu_gt::ownership::claim_legacy(gpu.function_addr(), gpu.gtt_mmadr)
            .map_err(|_| SubmitError::NoEngine)
    })
    .ok_or(SubmitError::NoEngine)?
}

fn attach_default(lease: &crate::intel_gpu_gt::ownership::LegacyLease) -> Result<(), SubmitError> {
    let (engine, fw_window) = crate::intel_gpu::with_controller(|gpu| {
        if !lease.matches_function(gpu.function_addr(), gpu.gtt_mmadr) {
            return None;
        }
        let arena = production_arena(gpu.gtt_mmadr);
        let engine = RcsEngine::new_for_generation(
            gpu.chip_info().generation,
            BarWindow::new(gpu.gtt_mmadr),
            arena,
        )
        .ok()?;
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
/// probed Gen12/Gen11 controller, attaching the RCS0 engine on first
/// use. Returns the engine-wide request id; completion is
/// observed through [`poll_default_completions`].
/// A pending, failed or stopped GuC owner still excludes this legacy path.
pub fn submit_dwords(dwords: &[u32]) -> Result<u64, SubmitError> {
    // PM gate first: a gated submission must not attach the
    // engine or touch hardware on its way to refusal.
    if submissions_gated() {
        return Err(SubmitError::Suspended);
    }
    let lease = legacy_submission_lease()?;
    let mut guard = RCS_STATE.lock();
    if guard.is_none() {
        drop(guard);
        attach_default(&lease)?;
        guard = RCS_STATE.lock();
    }
    let (engine, default_ctx, fw, fw_window) = guard.as_mut().expect("attached above");
    if !lease.matches(fw_window.bar) {
        return Err(SubmitError::NoEngine);
    }
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
        /// Generation selecting the CSB depth and write-pointer
        /// dword this fake posts (`csb_entries` /
        /// `csb_write_byte`): Gen9 posts a 6-entry CSB at dword
        /// 0x1f, Gen11+ a 12-entry CSB at dword 0x2f.
        generation: crate::intel_gpu::Generation,
        write_ptr: u8,
        consumed_elsp: usize,
        user_batches: BTreeMap<(u64, u64), alloc::sync::Weak<crate::intel_gpu_gem::GemObject>>,
        /// 3D (GFXPIPE) commands executed from GGTT batches; a context that
        /// ran any saves [`SAVED_3D_MARKER`] into its engine state.
        gfx_commands: u32,
    }

    /// Where the fake "saves" 3D state in a render image: page 2, past the
    /// register state the driver writes.
    const SAVED_3D_BYTE: u64 = 2 * GTT_PAGE_SIZE;
    const SAVED_3D_MARKER: u32 = 0x3d3d_0000;

    impl FakeHw {
        fn new(regs: FakeRegs, registry: FakeObjectRegistry, status_ggtt: u32) -> Self {
            Self::for_generation(
                regs,
                registry,
                status_ggtt,
                crate::intel_gpu::Generation::TigerLake,
            )
        }

        fn for_generation(
            regs: FakeRegs,
            registry: FakeObjectRegistry,
            status_ggtt: u32,
            generation: crate::intel_gpu::Generation,
        ) -> Self {
            Self {
                regs,
                registry,
                status_ggtt,
                generation,
                write_ptr: 0,
                consumed_elsp: 0,
                user_batches: BTreeMap::new(),
                gfx_commands: 0,
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
            let queue = uses_submit_queue(self.generation);
            let sq = RCS0_SPEC.execlist_sq();
            let elsp: Vec<(u64, u32)> = self
                .regs
                .writes
                .borrow()
                .iter()
                .filter(|(o, _)| {
                    if queue {
                        (sq..sq + 16).contains(o)
                    } else {
                        *o == RING_ELSP
                    }
                })
                .copied()
                .collect();
            while self.consumed_elsp + 4 <= elsp.len() {
                let g = &elsp[self.consumed_elsp..self.consumed_elsp + 4];
                self.consumed_elsp += 4;
                let (port0, port1) = if queue {
                    // Port 1 low/high at +8/+12, then port 0 low/high.
                    assert_eq!(
                        [g[0].0, g[1].0, g[2].0, g[3].0],
                        [sq + 8, sq + 12, sq, sq + 4],
                        "submit queue write order"
                    );
                    (
                        ((g[3].1 as u64) << 32) | g[2].1 as u64,
                        ((g[1].1 as u64) << 32) | g[0].1 as u64,
                    )
                } else {
                    (
                        ((g[2].1 as u64) << 32) | g[3].1 as u64,
                        ((g[0].1 as u64) << 32) | g[1].1 as u64,
                    )
                };
                if port0 == 0 {
                    continue;
                }
                if gen8_csb(self.generation) {
                    // Gen8 format: status in the low dword, the context's
                    // descriptor id dword in the high one.
                    let id = |desc: u64| (desc >> 32) as u32;
                    self.push_csb(CsbEntry {
                        lower: GEN8_CSB_IDLE_ACTIVE,
                        upper: id(port0),
                    });
                    self.execute(port0);
                    if port1 != 0 {
                        // COMPLETE | ELEMENT_SWITCH, then COMPLETE | ACTIVE_IDLE.
                        self.push_csb(CsbEntry {
                            lower: 1 << 4 | 1 << 2,
                            upper: id(port0),
                        });
                        self.execute(port1);
                        self.push_csb(CsbEntry {
                            lower: 1 << 4 | 1 << 3,
                            upper: id(port1),
                        });
                    } else {
                        self.push_csb(CsbEntry {
                            lower: 1 << 4 | 1 << 3,
                            upper: id(port0),
                        });
                    }
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
            let gfx_before = self.gfx_commands;
            let mut stop = None;
            while pos != tail && guard < RING_BYTES {
                guard += 4;
                let dw = mem_rd(&ring, pos as u64);
                match dw >> 23 {
                    0xf4 => {
                        // PIPE_CONTROL is six dwords. The post-sync QW write
                        // follows a separate cache drain/stall command.
                        assert_eq!(dw & 0xff, 4, "PIPE_CONTROL length");
                        let flags = mem_rd(&ring, ((pos + 4) & mask) as u64);
                        // Store-data-index posts into the context's PPHWSP
                        // scratch (the Gen9/Gen11 invalidate): no GGTT write.
                        if flags & (1 << 14) != 0 && flags & (1 << 21) == 0 {
                            assert_ne!(flags & (1 << 24), 0, "post-sync must use GGTT");
                            let lo = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                            let hi = mem_rd(&ring, ((pos + 12) & mask) as u64) as u64;
                            let data = mem_rd(&ring, ((pos + 16) & mask) as u64);
                            self.write_ggtt(lo | (hi << 32), data);
                            self.write_ggtt((lo | (hi << 32)) + 4, 0);
                        }
                        pos = (pos + 24) & mask;
                    }
                    0x26 => {
                        let lo = mem_rd(&ring, ((pos + 4) & mask) as u64) as u64;
                        let hi = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                        let data = mem_rd(&ring, ((pos + 12) & mask) as u64);
                        // Store-index posts into the context's PPHWSP scratch
                        // (the Gen9/Gen11 XCS invalidate): no GGTT write.
                        if dw & (1 << 21) == 0 {
                            self.write_ggtt((lo & !7) | (hi << 32), data);
                        }
                        pos = (pos + 16) & mask;
                    }
                    0x31 => {
                        let lo = mem_rd(&ring, ((pos + 4) & mask) as u64) as u64;
                        let hi = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                        let address = lo | (hi << 32);
                        if let Ok(ggtt) = u32::try_from(address) {
                            self.execute_batch(ggtt);
                        } else {
                            assert_ne!(dw & 0x100, 0, "user batch needs PPGTT");
                            let root = mem_rd(&image, rs + ((CTX_PDP3_UDW + 15) as u64) * 4) as u64
                                | ((mem_rd(&image, rs + ((CTX_PDP3_UDW + 13) as u64) * 4) as u64)
                                    << 32);
                            let object = self
                                .user_batches
                                .get(&(root, address))
                                .and_then(alloc::sync::Weak::upgrade)
                                .expect("resident PPGTT batch");
                            let mut bytes = [0; 8];
                            object.read(0, &mut bytes).expect("batch bytes");
                            assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0, 5]);
                        }
                        pos = (pos + 12) & mask;
                    }
                    0x20 => {
                        let lo = mem_rd(&ring, ((pos + 4) & mask) as u64) as u64;
                        let hi = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                        let data = mem_rd(&ring, ((pos + 12) & mask) as u64);
                        self.write_ggtt(lo | (hi << 32), data);
                        pos = (pos + 16) & mask;
                    }
                    0x1c => {
                        // MI_SEMAPHORE_WAIT (poll, equal): a paused ring stops
                        // here, as the hardware busywaits, and saves its head.
                        let data = mem_rd(&ring, ((pos + 4) & mask) as u64);
                        let lo = mem_rd(&ring, ((pos + 8) & mask) as u64) as u64;
                        let hi = mem_rd(&ring, ((pos + 12) & mask) as u64) as u64;
                        if self.read_ggtt(lo | (hi << 32)) != data {
                            stop = Some(pos);
                            break;
                        }
                        pos = (pos + 16) & mask;
                    }
                    _ => pos = (pos + 4) & mask,
                }
            }
            if self.gfx_commands != gfx_before {
                mem_wr(&image, SAVED_3D_BYTE, SAVED_3D_MARKER | self.gfx_commands);
            }
            mem_wr(
                &image,
                rs + ((CTX_RING_HEAD + 1) as u64) * 4,
                stop.unwrap_or(tail),
            );
        }

        fn execute_batch(&mut self, ggtt: u32) {
            let batch = self.mem(ggtt);
            let len = batch.borrow().len() as u64;
            let mut pos = 0u64;
            while pos + 4 <= len {
                let dw = mem_rd(&batch, pos);
                if dw >> 29 == 3 {
                    // GFXPIPE: step over by length. PIPELINE_SELECT and
                    // VF_STATISTICS are single dwords; SO_DECL_LIST has a
                    // nine-bit length.
                    self.gfx_commands += 1;
                    pos += 4 * match dw >> 16 {
                        0x6904 | 0x680b => 1,
                        0x7917 => u64::from(dw & 0x1ff) + 2,
                        _ => u64::from(dw & 0xff) + 2,
                    };
                    continue;
                }
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

        fn read_ggtt(&self, addr: u64) -> u32 {
            let reg = self.registry.borrow();
            for (base, mem) in reg.iter() {
                let size = mem.borrow().len() as u64;
                if addr >= *base as u64 && addr + 4 <= *base as u64 + size {
                    return mem_rd(mem, addr - *base as u64);
                }
            }
            panic!("fake hw: load from unmapped GGTT address");
        }

        fn push_csb(&mut self, entry: CsbEntry) {
            self.write_ptr = (self.write_ptr + 1) % csb_entries(self.generation);
            let status = self.mem(self.status_ggtt);
            let off = CSB_BUF_BYTE + (self.write_ptr as u64) * 8;
            mem_wr(&status, off, entry.lower);
            mem_wr(&status, off + 4, entry.upper);
            mem_wr(
                &status,
                csb_write_byte(self.generation),
                self.write_ptr as u32,
            );
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

    fn make_engine_for_generation(
        generation: crate::intel_gpu::Generation,
    ) -> Result<(RcsEngine<FakeRegs, FakeArena>, FakeHw), TestResult> {
        let regs = FakeRegs::new();
        let registry = Rc::new(RefCell::new(BTreeMap::new()));
        let arena = FakeArena::new(registry.clone());
        let engine = match RcsEngine::new_for_generation(generation, regs.clone(), arena) {
            Ok(e) => e,
            Err(_) => return Err(TestResult::Fail("engine init")),
        };
        let hw = FakeHw::for_generation(regs, registry, engine.status_ggtt(), generation);
        Ok((engine, hw))
    }

    // ── Codec fixtures ──────────────────────────────────────

    fn smoke_render_cache_barrier() -> TestResult {
        // Linux v6.12 MIT gen8_engine_cs.c gen12_emit_fini_breadcrumb_rcs:
        // CS/TLB/tile/RT/depth/DC/LLC + Gen12 L3 and depth-stall workaround;
        // a distinct GGTT QW post-sync follows the cache drain.
        let words = render_breadcrumb(0x1234_0080, 7);
        if words
            != [
                0x7a00_0204,
                0x1814_30a1,
                0,
                0,
                0,
                0,
                0x7a00_0004,
                0x0110_4080,
                0x1234_0080,
                0,
                7,
                0,
            ]
        {
            return TestResult::Fail("Gen12 render barrier wire vector");
        }
        let (mut engine, _) = make_engine().unwrap();
        let ctx = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(ctx, batch).unwrap();
        if engine.context(ctx).unwrap().ring.tail % 8 != 0 {
            return TestResult::Fail("submitted ring tail is not qword aligned");
        }
        // SAFETY: this model has no running hardware or outstanding peer.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_render_cache_barrier);

    fn resident_fixture(
        hw: &mut FakeHw,
    ) -> (
        ResidentBatch,
        alloc::sync::Weak<crate::intel_gpu_gem::GemObject>,
    ) {
        resident_fixture_with(hw, crate::intel_gpu_gtt::PteFormat::Gen12)
    }

    fn resident_fixture_with(
        hw: &mut FakeHw,
        format: crate::intel_gpu_gtt::PteFormat,
    ) -> (
        ResidentBatch,
        alloc::sync::Weak<crate::intel_gpu_gem::GemObject>,
    ) {
        use crate::intel_gpu_exec::{ExecObject, ExecRequest};
        let gem = crate::intel_gpu_gem::GemState::new();
        let handle = gem.create(4096, |_, _| Ok(())).unwrap();
        let object = gem.object(handle).unwrap();
        object.write(0, &[0, 0, 0, 0, 0, 0, 0, 5]).unwrap();
        let weak = Arc::downgrade(&object);
        let va = 0x1234_0000_0000;
        let request = ExecRequest {
            ring: 0,
            context_id: 0,
            no_preempt: false,
            batch_va: va,
            batch_len: 8,
            objects: alloc::vec![ExecObject {
                object,
                va,
                writable: false,
                asynchronous: false,
                capture: false,
            }],
        };
        let batch = request.prepare(format, 0).unwrap();
        let translated = batch.space().translate(va).unwrap();
        assert!(
            matches!(translated, crate::intel_gpu_ppgtt::WalkOutcome::Mapped(phys)
            if phys == request.objects[0].object.pages().next().unwrap())
        );
        hw.user_batches
            .insert((batch.space().root_phys(), va), weak.clone());
        gem.close(handle).unwrap();
        (batch, weak)
    }

    fn smoke_owned_resident_completion() -> TestResult {
        let (mut engine, mut hw) = make_engine().unwrap();
        let ctx = engine.create_context().unwrap();
        let (batch, weak) = resident_fixture(&mut hw);
        let submission = engine.submit_resident(ctx, batch).unwrap();
        if weak.strong_count() != 1 || submission.fence.result().is_some() {
            return TestResult::Fail("job must own residency after fd close");
        }
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1
            || done[0].request != submission.request
            || weak.upgrade().is_some()
            || submission.fence.result() != Some(Ok(()))
            || engine.ppgtt_root(ctx) != Ok(None)
        {
            return TestResult::Fail("terminal completion did not release root and residency");
        }
        // SAFETY: all modelled requests completed; no peer runs afterwards.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_owned_resident_completion);

    fn smoke_completion_without_breadcrumb_retains() -> TestResult {
        let (mut engine, mut hw) = make_engine().unwrap();
        let ctx = engine.create_context().unwrap();
        let (batch, weak) = resident_fixture(&mut hw);
        let submission = engine.submit_resident(ctx, batch).unwrap();
        hw.inject_csb(csb_promote(1));
        hw.inject_csb(csb_complete(1, IDLE_SW_ID));
        if !engine.poll_completions().is_empty()
            || !engine.completion_lost()
            || submission.fence.result().is_some()
            || weak.strong_count() != 1
            || engine.is_idle()
        {
            return TestResult::Fail("unverified CSB event released a published job");
        }
        if engine.create_context() != Err(SubmitError::CompletionLost) {
            return TestResult::Fail("lost engine admitted new work");
        }
        drop(hw);
        // SAFETY: modelled GPU was never stepped and is now discarded. Reset
        // is terminal; neither a timeout nor the bogus CSB established this.
        unsafe {
            engine.release_after_reset();
        }
        if weak.upgrade().is_some() || submission.fence.result() != Some(Err(JobError::Reset)) {
            return TestResult::Fail("confirmed reset did not end residency with error");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_completion_without_breadcrumb_retains
    );

    fn smoke_completion_evidence_independent() -> TestResult {
        for corrupt in 0..3 {
            let (mut engine, mut hw) = make_engine().unwrap();
            let ctx = engine.create_context().unwrap();
            let (batch, weak) = resident_fixture(&mut hw);
            let submission = engine.submit_resident(ctx, batch).unwrap();
            hw.step();
            let context = engine.context(ctx).unwrap();
            match corrupt {
                0 => context.hwsp.write32(HWSP_SEQNO_BYTE, 0),
                1 => context
                    .image
                    .write32(REG_STATE_PAGE_BYTE + ((CTX_RING_HEAD + 1) as u64) * 4, 0),
                _ => engine.status.write32(CSB_WRITE_BYTE, 0xff),
            }
            if !engine.poll_completions().is_empty()
                || !engine.completion_lost()
                || weak.strong_count() != 1
                || submission.fence.result().is_some()
            {
                return TestResult::Fail("incomplete breadcrumb/head/cursor proof retired work");
            }
            drop(hw);
            // SAFETY: the modelled peer has stopped; no descriptor can run.
            unsafe {
                engine.release_after_reset();
            }
            if weak.upgrade().is_some() {
                return TestResult::Fail("reset retained rejected completion");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_completion_evidence_independent
    );

    fn smoke_queued_context_root_is_frozen() -> TestResult {
        let (mut engine, _) = make_engine().unwrap();
        let first = engine.create_context().unwrap();
        let queued = engine.create_context().unwrap();
        for ctx in [first, queued] {
            let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
            engine.submit(ctx, batch).unwrap();
        }
        if engine.attach_ppgtt(queued, 0x400000) != Err(SubmitError::ContextBusy)
            || engine.detach_ppgtt(queued) != Err(SubmitError::ContextBusy)
            || engine.ppgtt_root(queued) != Ok(None)
        {
            return TestResult::Fail("queued request's root could be replaced");
        }
        // SAFETY: the model has no running hardware or outstanding peer.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_queued_context_root_is_frozen
    );

    fn smoke_preempted_residency_survives() -> TestResult {
        let (mut engine, mut hw) = make_engine().unwrap();
        let ctx = engine.create_context().unwrap();
        let (batch, weak) = resident_fixture(&mut hw);
        let submission = engine.submit_resident(ctx, batch).unwrap();
        hw.inject_csb(csb_promote(1));
        hw.inject_csb(csb_preempt(1, IDLE_SW_ID));
        if !engine.poll_completions().is_empty()
            || weak.strong_count() != 1
            || submission.fence.result().is_some()
        {
            return TestResult::Fail("preemption released resident work");
        }
        // Discard the superseded initial ELSP burst; model the resubmission.
        hw.consumed_elsp = 4;
        hw.step();
        if engine.poll_completions().len() != 1
            || weak.upgrade().is_some()
            || submission.fence.result() != Some(Ok(()))
        {
            return TestResult::Fail("preempted resident job did not resume");
        }
        // SAFETY: the model has completed and no peer runs afterwards.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_preempted_residency_survives
    );

    fn smoke_context_csb_identity_not_reused() -> TestResult {
        let (mut engine, mut hw) = make_engine().unwrap();
        let old = engine.create_context().unwrap();
        engine.destroy_context(old).unwrap();
        let new = engine.create_context().unwrap();
        if new.slot() != old.slot() || engine.context(new).unwrap().sw_id != 2 {
            return TestResult::Fail("CSB identity reused after context slot reuse");
        }
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(new, batch).unwrap();
        hw.inject_csb(csb_promote(2));
        hw.inject_csb(csb_complete(1, IDLE_SW_ID));
        if !engine.poll_completions().is_empty() || engine.completion_lost() {
            return TestResult::Fail("old context event matched a replacement job");
        }
        hw.step();
        if engine.poll_completions().len() != 1 {
            return TestResult::Fail("replacement context completion lost");
        }
        // SAFETY: the model has completed and no peer runs afterwards.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_context_csb_identity_not_reused
    );

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

    fn smoke_gen11_reg_state_template() -> TestResult {
        // MIT intel_lrc.c `gen11_rcs_offsets`: 15-pair first group
        // with the second-level batch registers, a single-pair
        // third group, no 51-register extended group, terminator
        // at 0x44.
        let r = build_reg_state_for_generation(
            &RCS0_SPEC,
            0x1004_0000,
            RING_BYTES,
            crate::intel_gpu::Generation::IceLake,
        );
        if r[0] != MI_NOOP || r[CTX_LRI_HEADER_0] != 0x1108_101d {
            return TestResult::Fail("Gen11 group 0 header");
        }
        if r[CTX_CONTEXT_CONTROL] != RING_CONTEXT_CONTROL as u32
            || r[CTX_CONTEXT_CONTROL + 1] != CTX_CONTROL_VALUE
        {
            return TestResult::Fail("Gen11 context control pair");
        }
        if r[CTX_RING_TAIL] != RING_TAIL as u32 || r[CTX_RING_TAIL + 1] != 0 {
            return TestResult::Fail("Gen11 ring tail pair");
        }
        if r[CTX_RING_BUFFER_START] != RING_START as u32
            || r[CTX_RING_BUFFER_START + 1] != 0x1004_0000
        {
            return TestResult::Fail("Gen11 ring start pair");
        }
        if r[CTX_RING_BUFFER_CONTROL + 1] != 0x1_f001 {
            return TestResult::Fail("Gen11 ring ctl value");
        }
        // Second-level batch registers Gen12 drops, in template order.
        if r[0x12] != 0x211c || r[0x13] != 0 {
            return TestResult::Fail("Gen11 SBBADDR_UDW pair");
        }
        if r[0x14] != 0x2114 || r[0x15] != 0 {
            return TestResult::Fail("Gen11 SBBADDR pair");
        }
        if r[0x16] != 0x2118 || r[0x17] != 0 {
            return TestResult::Fail("Gen11 SBBSTATE pair");
        }
        // The workaround-batch and indirect-context pairs sit
        // six dwords later than on Gen12.
        if r[GEN11_CTX_BB_PER_CTX_PTR] != RING_BB_PER_CTX_PTR as u32
            || r[GEN11_CTX_BB_PER_CTX_PTR + 1] != 0
        {
            return TestResult::Fail("Gen11 BB per-ctx pair");
        }
        if r[GEN11_CTX_RCS_INDIRECT_CTX] != RING_INDIRECT_CTX as u32
            || r[GEN11_CTX_RCS_INDIRECT_CTX + 1] != 0
        {
            return TestResult::Fail("Gen11 indirect ctx pair");
        }
        if r[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET] != RING_INDIRECT_CTX_OFFSET as u32
            || r[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] != 0x1a << 6
        {
            return TestResult::Fail("Gen11 indirect ctx offset value");
        }
        // No Gen12 0x2b4 tail register: the last first-group
        // pair is 0x180.
        if r[0x1e] != 0x2180 || r[0x1f] != 0 {
            return TestResult::Fail("Gen11 first group tail");
        }
        if r[CTX_LRI_HEADER_1] != 0x1108_1011 {
            return TestResult::Fail("Gen11 group 1 header");
        }
        if r[CTX_PDP3_UDW] != ring_pdp_udw(3) as u32 || r[CTX_PDP3_UDW + 1] != 0 {
            return TestResult::Fail("Gen11 PDP3 pair");
        }
        // Third group: a single 0x1b0 pair; the Gen12 0x5a8 /
        // 0x5ac pairs and the 51-register group are absent.
        if r[0x34] != 0x1108_1001 || r[0x35] != 0x21b0 || r[0x36] != 0 {
            return TestResult::Fail("Gen11 third group");
        }
        if r[0x37] != 0 || r[0x39] != 0 || r[0x51] != 0 {
            return TestResult::Fail("Gen11 must not carry Gen12 extended groups");
        }
        if r[CTX_LRI_HEADER_2] != 0x1108_0001 || r[CTX_R_PWR_CLK_STATE] != R_PWR_CLK_STATE as u32 {
            return TestResult::Fail("Gen11 group 2 (RCS power clock state)");
        }
        if r[GEN11_CTX_RCS_END] != MI_BATCH_BUFFER_END | 1 {
            return TestResult::Fail("Gen11 template terminator");
        }
        if r[GEN11_CTX_RCS_END + 1] != 0 || r[CTX_END] != 0 {
            return TestResult::Fail("Gen11 template must end at 0x44");
        }
        // The Gen12 template is byte-identical through the
        // refactor.
        if build_reg_state(0x1004_0000, RING_BYTES)
            != build_reg_state_for_generation(
                &RCS0_SPEC,
                0x1004_0000,
                RING_BYTES,
                crate::intel_gpu::Generation::TigerLake,
            )
        {
            return TestResult::Fail("Gen12 template drifted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen11_reg_state_template);

    fn smoke_gen11_reg_state_xcs() -> TestResult {
        // MIT intel_lrc.c `gen9_xcs_offsets` (the Gen11 XCS
        // table): 14-pair first group, the 0x200 pair at 0x42,
        // the 44-register group at 0x51, terminator at 0xaa.
        let t = build_reg_state_for_generation(
            &crate::intel_gpu_media::VECS0_SPEC,
            0x1000_5000,
            RING_BYTES,
            crate::intel_gpu::Generation::IceLake,
        );
        if t[CTX_LRI_HEADER_0] != 0x1108_101b {
            return TestResult::Fail("Gen11 XCS group 0 header");
        }
        if t[CTX_CONTEXT_CONTROL] != 0x1C_8244 {
            return TestResult::Fail("Gen11 XCS context control address");
        }
        if t[0x12] != 0x1C_811C || t[0x14] != 0x1C_8114 || t[0x16] != 0x1C_8118 {
            return TestResult::Fail("Gen11 XCS second-level batch pairs");
        }
        if t[GEN11_CTX_BB_PER_CTX_PTR] != 0x1C_81C0
            || t[GEN11_CTX_RCS_INDIRECT_CTX] != 0x1C_81C4
            || t[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET] != 0x1C_81C8
            || t[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] != 0
        {
            return TestResult::Fail("Gen11 XCS indirect ctx pairs");
        }
        // No trailing 0x180 in the XCS first group: 0x1e is a NOP.
        if t[0x1e] != 0 {
            return TestResult::Fail("Gen11 XCS first group tail");
        }
        if t[CTX_LRI_HEADER_1] != 0x1108_1011 || t[CTX_PDP3_UDW] != 0x1C_828C {
            return TestResult::Fail("Gen11 XCS PDP group");
        }
        // No Gen12 XCS terminator at 0x34: that slot is a NOP.
        if t[CTX_XCS_END] != 0 {
            return TestResult::Fail("Gen11 XCS must not end at 0x34");
        }
        if t[0x41] != 0x1108_1001 || t[0x42] != 0x1C_8200 || t[0x43] != 0 {
            return TestResult::Fail("Gen11 XCS 0x200 pair");
        }
        if t[0x51] != 0x1108_1057 || t[0x52] != 0x1C_8028 || t[0xA8] != 0x1C_8068 {
            return TestResult::Fail("Gen11 XCS 44-register group");
        }
        // No render group: the R_PWR_CLK_STATE register address
        // (0x20C8, `GEN8_R_PWR_CLK_STATE`) appears nowhere in the
        // template. The render pair lives only in the RCS tables
        // (`gen11_rcs_offsets`: non-posted LRI-1 at 0x41, 0x20C8
        // at 0x42); on XCS those same slots are the 0x200 pair
        // (`gen9_xcs_offsets`: posted LRI-1 at 0x41, base+0x200
        // at 0x42), already pinned by the 0x200-pair check above
        // — so a zero check on `CTX_LRI_HEADER_2` /
        // `CTX_R_PWR_CLK_STATE` here would contradict it.
        if t.contains(&(R_PWR_CLK_STATE as u32)) {
            return TestResult::Fail("Gen11 XCS template carries render group");
        }
        if t[GEN11_CTX_XCS_END] != MI_BATCH_BUFFER_END | 1 {
            return TestResult::Fail("Gen11 XCS template terminator");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen11_reg_state_xcs);

    fn smoke_gen11_context_image_bound() -> TestResult {
        // MIT intel_engine_cs.c `intel_engine_context_size`:
        // Gen11 and Gen12 render images are both
        // GEN11_LR_CONTEXT_RENDER_SIZE (14 pages); non-render
        // images are GEN8_LR_CONTEXT_OTHER_SIZE (2 pages) on
        // every Gen8+ generation. The CSB depth is
        // GEN11_CSB_ENTRIES (12) from graphics 11 on.
        if RENDER_IMAGE_PAGES != 14 || RCS_IMAGE_PAGES < RENDER_IMAGE_PAGES {
            return TestResult::Fail("Gen11 render image bound");
        }
        if OTHER_IMAGE_PAGES != 2 {
            return TestResult::Fail("Gen11 non-render image bound");
        }
        if CSB_ENTRIES != 12 {
            return TestResult::Fail("Gen11 CSB depth");
        }
        // MIT intel_lrc_reg.h: Gen11 0x1a, Gen12 0xd.
        if indirect_ctx_offset_default(crate::intel_gpu::Generation::IceLake) != 0x1a
            || indirect_ctx_offset_default(crate::intel_gpu::Generation::TigerLake) != 0x0d
            || indirect_ctx_offset_default(crate::intel_gpu::Generation::AlderLake) != 0x0d
        {
            return TestResult::Fail("indirect ctx offset defaults");
        }
        // Gen12 keeps its existing (zero) template value.
        let gen12 = build_reg_state(0x1004_0000, RING_BYTES);
        if gen12[CTX_RCS_INDIRECT_CTX_OFFSET + 1] != 0 {
            return TestResult::Fail("Gen12 indirect ctx offset value changed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen11_context_image_bound);

    fn smoke_gen9_reg_state_rcs() -> TestResult {
        // MIT intel_lrc.c `gen9_rcs_offsets`: 14-pair first
        // group (no trailing 0x180), the 9-pair PDP group, the
        // single-pair R_PWR_CLK_STATE group (LRI(1, 0), 0xc8),
        // then the 44-register group, terminator at 0xaa. The
        // LRI headers carry no MI_LRI_LRM_CS_MMIO bit
        // (`set_offsets` sets it only for graphics 11+), so
        // every header here is the bare `mi_load_register_imm`
        // encoding — 0x1100101b, not the Gen11 0x1108101b.
        let t = build_reg_state_for_generation(
            &RCS0_SPEC,
            0x1000_5000,
            RING_BYTES,
            crate::intel_gpu::Generation::Skylake,
        );
        if t[0] != MI_NOOP || t[CTX_LRI_HEADER_0] != 0x1100_101b {
            return TestResult::Fail("Gen9 RCS group 0 header");
        }
        if t[CTX_CONTEXT_CONTROL] != 0x2244 || t[CTX_CONTEXT_CONTROL + 1] != 0x000F_0008 {
            return TestResult::Fail("Gen9 RCS context control pair");
        }
        if t[CTX_RING_HEAD] != 0x2034
            || t[CTX_RING_TAIL] != 0x2030
            || t[CTX_RING_BUFFER_START] != 0x2038
            || t[CTX_RING_BUFFER_START + 1] != 0x1000_5000
            || t[CTX_RING_BUFFER_CONTROL] != 0x203c
            || t[CTX_RING_BUFFER_CONTROL + 1] != ring_ctl_value(RING_BYTES)
        {
            return TestResult::Fail("Gen9 RCS ring pairs");
        }
        if t[0x12] != 0x211c || t[0x14] != 0x2114 || t[0x16] != 0x2118 {
            return TestResult::Fail("Gen9 RCS second-level batch pairs");
        }
        if t[GEN11_CTX_BB_PER_CTX_PTR] != 0x21c0
            || t[GEN11_CTX_RCS_INDIRECT_CTX] != 0x21c4
            || t[GEN11_CTX_RCS_INDIRECT_CTX + 1] != 0
            || t[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET] != 0x21c8
            || t[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] != 0x26 << 6
        {
            return TestResult::Fail("Gen9 RCS indirect ctx pairs");
        }
        // No trailing 0x180 in the first group: 0x1e is a NOP.
        if t[0x1e] != 0 {
            return TestResult::Fail("Gen9 RCS first group tail");
        }
        // No 0x1b0 third group: 0x34 is a NOP.
        if t[0x34] != 0 {
            return TestResult::Fail("Gen9 RCS must have no 0x1b0 group");
        }
        if t[CTX_LRI_HEADER_1] != 0x1100_1011 || t[CTX_CTX_TIMESTAMP] != 0x23a8 {
            return TestResult::Fail("Gen9 RCS PDP group");
        }
        if t[0x41] != 0x1100_0001 || t[0x42] != 0x20c8 || t[0x43] != 0 {
            return TestResult::Fail("Gen9 RCS R_PWR_CLK_STATE pair");
        }
        if t[0x51] != 0x1100_1057 || t[0x52] != 0x2028 || t[0xA8] != 0x2068 {
            return TestResult::Fail("Gen9 RCS 44-register group");
        }
        if t[GEN11_CTX_XCS_END] != MI_BATCH_BUFFER_END | 1 {
            return TestResult::Fail("Gen9 RCS terminator");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen9_reg_state_rcs);

    fn smoke_gen9_reg_state_xcs() -> TestResult {
        // MIT intel_lrc.c `gen9_xcs_offsets` — the same table
        // the Gen11 XCS half already reuses, here without the
        // Gen11 RELATIVE bit: 14-pair first group, the 0x200
        // pair at 0x42, the 44-register group at 0x51,
        // terminator at 0xaa.
        let t = build_reg_state_for_generation(
            &crate::intel_gpu_media::VECS0_SPEC,
            0x1000_5000,
            RING_BYTES,
            crate::intel_gpu::Generation::Skylake,
        );
        if t[CTX_LRI_HEADER_0] != 0x1100_101b {
            return TestResult::Fail("Gen9 XCS group 0 header");
        }
        if t[CTX_CONTEXT_CONTROL] != 0x1C_8244 || t[CTX_CONTEXT_CONTROL + 1] != 0x000F_0008 {
            return TestResult::Fail("Gen9 XCS context control pair");
        }
        if t[0x1e] != 0 {
            return TestResult::Fail("Gen9 XCS first group tail");
        }
        if t[CTX_LRI_HEADER_1] != 0x1100_1011 || t[CTX_PDP3_UDW] != 0x1C_828C {
            return TestResult::Fail("Gen9 XCS PDP group");
        }
        if t[CTX_XCS_END] != 0 {
            return TestResult::Fail("Gen9 XCS must not end at 0x34");
        }
        if t[0x41] != 0x1100_1001 || t[0x42] != 0x1C_8200 || t[0x43] != 0 {
            return TestResult::Fail("Gen9 XCS 0x200 pair");
        }
        if t[0x51] != 0x1100_1057 || t[0x52] != 0x1C_8028 || t[0xA8] != 0x1C_8068 {
            return TestResult::Fail("Gen9 XCS 44-register group");
        }
        if t.contains(&(R_PWR_CLK_STATE as u32)) {
            return TestResult::Fail("Gen9 XCS template carries render group");
        }
        if t[GEN11_CTX_XCS_END] != MI_BATCH_BUFFER_END | 1 {
            return TestResult::Fail("Gen9 XCS terminator");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen9_reg_state_xcs);

    fn smoke_gen9_context_image_bound() -> TestResult {
        // MIT intel_engine_cs.c `intel_engine_context_size`:
        // Gen9 render images are GEN9_LR_CONTEXT_RENDER_SIZE
        // (22 pages); Gen11/Gen12 are 14. Non-render images are
        // GEN8_LR_CONTEXT_OTHER_SIZE (2 pages) on every Gen8+
        // generation. MIT intel_lrc_reg.h: Gen9 CSB depth is
        // GEN8_CSB_ENTRIES (6) with the write pointer at dword
        // 0x1f; Gen11+ is 12 at 0x2f. MIT intel_lrc_reg.h:
        // Gen9 indirect offset default is 0x26.
        if render_image_pages(crate::intel_gpu::Generation::Skylake) != 22
            || RCS_IMAGE_PAGES < render_image_pages(crate::intel_gpu::Generation::Skylake)
            || render_image_pages(crate::intel_gpu::Generation::IceLake) != 14
            || render_image_pages(crate::intel_gpu::Generation::TigerLake) != 14
        {
            return TestResult::Fail("Gen9 render image bound");
        }
        if OTHER_IMAGE_PAGES != 2 {
            return TestResult::Fail("Gen9 non-render image bound");
        }
        if csb_entries(crate::intel_gpu::Generation::Skylake) != 6
            || csb_entries(crate::intel_gpu::Generation::IceLake) != 12
            || csb_entries(crate::intel_gpu::Generation::TigerLake) != 12
        {
            return TestResult::Fail("Gen9 CSB depth");
        }
        if csb_write_dword(crate::intel_gpu::Generation::Skylake) != 0x1f
            || csb_write_dword(crate::intel_gpu::Generation::IceLake) != 0x2f
            || csb_write_byte(crate::intel_gpu::Generation::Skylake) != 0x7c
        {
            return TestResult::Fail("Gen9 CSB write pointer");
        }
        if indirect_ctx_offset_default(crate::intel_gpu::Generation::Skylake) != 0x26 {
            return TestResult::Fail("Gen9 indirect ctx offset default");
        }
        if ctx_control_value(crate::intel_gpu::Generation::Skylake) != 0x000F_0008
            || ctx_control_value(crate::intel_gpu::Generation::IceLake) != CTX_CONTROL_VALUE
        {
            return TestResult::Fail("Gen9 context control value");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen9_context_image_bound);

    fn smoke_gen9_descriptor() -> TestResult {
        // MIT intel_lrc.c `lrc_descriptor` +
        // `__execlists_schedule_in`: on Gen9 the upper dword
        // carries the SW context id at bits 37:47 and nothing
        // else — no engine instance (bits 48:53) or class (bits
        // 61:63); those are ORed in only for graphics 11+.
        let gen9 = crate::intel_gpu::Generation::Skylake;
        let d = context_descriptor_for_generation(&RCS0_SPEC, 0x1000_0000, 5, gen9);
        if d & DESC_VALID == 0 {
            return TestResult::Fail("Gen9 VALID bit clear");
        }
        if d & DESC_MODE_LEGACY_64B != DESC_MODE_LEGACY_64B {
            return TestResult::Fail("Gen9 mode is not Legacy-64B");
        }
        if d & DESC_PRIVILEGE == 0 {
            return TestResult::Fail("Gen9 privilege flag lost");
        }
        if descriptor_lrca(d) != 0x1000_0000 {
            return TestResult::Fail("Gen9 LRCA round-trip");
        }
        if descriptor_sw_id(d) != 5 {
            return TestResult::Fail("Gen9 SW id round-trip");
        }
        // Upper dword: exactly the SW id field (bits 37:47).
        if (d >> 32) != (5u64 << 5) {
            return TestResult::Fail("Gen9 upper dword carries instance/class bits");
        }
        if descriptor_instance(d) != 0 || descriptor_class(d) != 0 {
            return TestResult::Fail("Gen9 descriptor names an instance/class");
        }
        // Contrast: the Gen11+ form packs instance + class.
        let vcs1 = crate::intel_gpu_media::VCS1_SPEC;
        let d11 = context_descriptor_for_generation(&vcs1, 0x1000_0000, 7, gen9);
        // (Gen9 descriptor for a media spec still carries no
        // instance/class — the generation selects the layout,
        // not the engine.)
        if (d11 >> 32) != (7u64 << 5) {
            return TestResult::Fail("Gen9 media descriptor carries instance/class bits");
        }
        let d11 = context_descriptor_for_generation(
            &vcs1,
            0x1000_0000,
            7,
            crate::intel_gpu::Generation::IceLake,
        );
        if (d11 >> 32) != (7u64 << 5) | (1u64 << 16) | (1u64 << 29) {
            return TestResult::Fail("Gen11 descriptor upper dword");
        }
        if descriptor_instance(d11) != 1 || descriptor_class(d11) != 1 {
            return TestResult::Fail("Gen11 descriptor instance/class round-trip");
        }
        // The plain constructor keeps the Gen11+ form.
        if context_descriptor_for(&vcs1, 0x1000_0000, 7) != d11 {
            return TestResult::Fail("plain descriptor constructor changed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen9_descriptor);

    fn smoke_gen9_indirectctx_bb() -> TestResult {
        // MIT intel_lrc.c `gen9_init_indirectctx_bb` wire
        // vector (non-pooled-EU): MI_ARB_DISABLE, the
        // coherent-L3 save/load/pipe-control/restore, the
        // ClearSlm pipe-control, the three-chicken LRI group,
        // MI_ARB_ENABLE, NOOP padding to the cacheline.
        let mut batch = [0u32; GEN9_INDIRECT_CTX_BB_DWORDS];
        let n = gen9_init_indirectctx_bb(&mut batch, false, 0x1234_5000);
        if n != GEN9_INDIRECT_CTX_BB_DWORDS {
            return TestResult::Fail("Gen9 WA batch length");
        }
        let want: [u32; 33] = [
            0x0400_0000, // MI_ARB_DISABLE
            0x1240_0002,
            0x0000_B118,
            0x1234_5000,
            0x0000_0000, // save L3SQCREG4
            0x1100_0001,
            0x0000_B118,
            0x4060_0000, // load flush bit
            0x7A00_0004,
            0x0010_0020,
            0,
            0,
            0,
            0, // pipe-control
            0x14C0_0002,
            0x0000_B118,
            0x1234_5000,
            0x0000_0000, // restore L3SQCREG4
            0x7A00_0004,
            0x0830_4000,
            0x0000_00D0,
            0,
            0,
            0, // ClearSlm pipe-control
            0x1100_0005,
            0x0000_7014,
            0x1000_0000,
            0x0000_2088,
            0x0002_0002,
            0x0000_2090,
            0x1000_1000,
            0x0000_0000, // chicken LRI group + NOOP
            0x0400_0001, // MI_ARB_ENABLE
        ];
        if batch[..33] != want {
            return TestResult::Fail("Gen9 WA batch wire vector");
        }
        if batch[33..].iter().any(|&w| w != MI_NOOP) {
            return TestResult::Fail("Gen9 WA batch padding");
        }
        // Pooled-EU: the media-pool sequence lands between the
        // chicken group and MI_ARB_ENABLE.
        let mut pooled = [0u32; GEN9_INDIRECT_CTX_BB_DWORDS];
        let n = gen9_init_indirectctx_bb(&mut pooled, true, 0x1234_5000);
        if n != GEN9_INDIRECT_CTX_BB_DWORDS {
            return TestResult::Fail("Gen9 pooled WA batch length");
        }
        if pooled[..32] != batch[..32] {
            return TestResult::Fail("Gen9 pooled WA batch prefix");
        }
        if pooled[32] != GEN9_MEDIA_POOL_STATE
            || pooled[33] != GEN9_MEDIA_POOL_ENABLE
            || pooled[34] != 0x0077_7000
            || pooled[35] != 0
            || pooled[36] != 0
            || pooled[37] != 0
            || pooled[38] != MI_ARB_ENABLE
        {
            return TestResult::Fail("Gen9 pooled media-pool sequence");
        }
        if pooled[39..].iter().any(|&w| w != MI_NOOP) {
            return TestResult::Fail("Gen9 pooled WA batch padding");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen9_indirectctx_bb);

    fn smoke_gen9_indirect_ctx_setup() -> TestResult {
        let mut regs = build_reg_state_for_generation(
            &RCS0_SPEC,
            0x1000_5000,
            RING_BYTES,
            crate::intel_gpu::Generation::Skylake,
        );
        // Three cachelines of WA batch at a GGTT address.
        setup_gen9_indirect_ctx(&mut regs, 0x2000_0000, 3 * 64);
        if regs[GEN11_CTX_RCS_INDIRECT_CTX + 1] != 0x2000_0003 {
            return TestResult::Fail("Gen9 indirect ctx pointer");
        }
        if regs[GEN11_CTX_RCS_INDIRECT_CTX_OFFSET + 1] != 0x26 << 6 {
            return TestResult::Fail("Gen9 indirect ctx offset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen9_indirect_ctx_setup);

    fn smoke_gen9_batch_executes_on_rcs() -> TestResult {
        let (mut engine, mut hw) =
            make_engine_for_generation(crate::intel_gpu::Generation::Skylake).unwrap();
        let ctx = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        let request = engine.submit(ctx, batch).unwrap();
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].request != request || !engine.is_idle() {
            return TestResult::Fail("Gen9 batch did not execute to completion on RCS");
        }
        // SAFETY: the model has completed and no peer runs afterwards.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen9_batch_executes_on_rcs
    );

    fn smoke_gen11_batch_executes_on_rcs() -> TestResult {
        let (mut engine, mut hw) =
            make_engine_for_generation(crate::intel_gpu::Generation::IceLake).unwrap();
        let ctx = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        let request = engine.submit(ctx, batch).unwrap();
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].request != request || !engine.is_idle() {
            return TestResult::Fail("Gen11 batch did not execute to completion on RCS");
        }
        // SAFETY: the model has completed and no peer runs afterwards.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen11_batch_executes_on_rcs
    );

    fn smoke_gen11_legacy_submission_needs_no_guc() -> TestResult {
        // Lane 7 item 3: execlists admission for Gen11 takes only the
        // generation — no GuC profile, image or owner is consulted — so a
        // Gen11 part submits with no GuC loaded. Execution evidence is
        // `smoke_gen11_batch_executes_on_rcs` above.
        if !legacy_submission_generation(crate::intel_gpu::Generation::IceLake)
            || legacy_submission_generation(crate::intel_gpu::Generation::MeteorLake)
            || legacy_submission_generation(crate::intel_gpu::Generation::LunarLake)
        {
            return TestResult::Fail("Gen11 legacy submission admission");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen11_legacy_submission_needs_no_guc
    );

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
        // Only 40 bytes free, but wrapping 28 bytes also consumes 16 bytes
        // of padding. Reject before writing either padding or command data.
        let mut tight = RingState {
            head: 32,
            tail: RING_BYTES - 16,
        };
        let previous = mem.read32(0);
        if ring_emit(&mem, &mut tight, &prog) != Err(SubmitError::RingFull)
            || tight.tail != RING_BYTES - 16
            || mem.read32(0) != previous
        {
            return TestResult::Fail("wrap padding overran unread ring contents");
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

    fn smoke_legacy_arena_gen12_dma39_and_qualified_dg2_dma46() -> TestResult {
        // The encoder never dereferences this sentinel BAR. Exercise the real
        // arena admission path without requiring a particular physical allocator.
        let mut arena = GgttArena::new(narf_bus::bar::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        });
        let last_gen12_page = (1u64 << 39) - 4096;
        if arena.encode_pte(last_gen12_page) != Ok(last_gen12_page | 1)
            || arena.encode_pte(1u64 << 39) != Err(crate::intel_gpu_gtt::GttError::PhysOutOfRange)
            || arena.encode_pte(4097).is_ok()
        {
            return TestResult::Fail("legacy arena did not enforce Gen12 DMA39 before mapping");
        }
        arena.policy = Some(crate::intel_gpu_gt_hw::CachePolicy {
            platform: crate::intel_gpu_gt::GtPlatform::Alchemist,
            ggtt_pat: 0,
            media: None,
        });
        let last_dg2_page = (1u64 << 46) - 4096;
        if arena.encode_pte(1u64 << 39) != Ok((1u64 << 39) | 1)
            || arena.encode_pte(last_dg2_page) != Ok(last_dg2_page | 1)
            || arena.encode_pte(1u64 << 46) != Err(crate::intel_gpu_gtt::GttError::PhysOutOfRange)
        {
            return TestResult::Fail("qualified DG2 arena lost its distinct DMA46 encoding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_legacy_arena_gen12_dma39_and_qualified_dg2_dma46
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
        for invalid in [1u64 << 39, 1u64 << 46] {
            match engine.attach_ppgtt(ctx, invalid) {
                Err(SubmitError::InvalidPpgttRoot) => {}
                _ => return TestResult::Fail("root outside Gen12 DMA mask must be refused"),
            }
            if engine.ppgtt_root(ctx) != Ok(None)
                || (0..4).any(|pair| pdp_val(pair, true) != 0 || pdp_val(pair, false) != 0)
            {
                return TestResult::Fail("invalid DMA root mutated the retained context image");
            }
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

    /// The Gen9/Gen11 request stream, hand-expanded from gen8_engine_cs.c.
    fn smoke_legacy_request_stream_follows_linux() -> TestResult {
        let start = mi_batch_buffer_start_ppgtt(0x1_2345_6000);
        let gen9 = legacy_render_request(false, start, 0xabc0, 7, 0x1000_00c8);
        let want9: [u32; 40] = [
            0x7a00_0004,
            0,
            0,
            0,
            0,
            0, // VF invalidate needs a null PIPE_CONTROL first
            0x7a00_0004,
            0x0034_4c1c,
            0xd0,
            0,
            0,
            0, // EMIT_INVALIDATE into PPHWSP scratch
            0x0400_0001,
            start[0],
            start[1],
            start[2],
            0x0400_0000,
            0, // ARB on across the batch, then off
            0x7a00_0004,
            0x0014_1021,
            0,
            0,
            0,
            0, // fini flush
            0x7a00_0004,
            0x0110_4080,
            0xabc0,
            0,
            7,
            0, // GGTT seqno
            0x0100_0000,
            0x0400_0001, // user interrupt, ARB on
            0x0280_0000,
            0x0e40_c002,
            0,
            0x1000_00c8,
            0,
            0, // preempt busywait on I915_GEM_HWS_PREEMPT
            0x0280_0000,
            0, // MI_ARB_CHECK, MI_NOOP
        ];
        if gen9 != want9 {
            return TestResult::Fail("Gen9 render request");
        }
        let gen11 = legacy_render_request(true, start, 0xabc0, 7, 0x1000_00c8);
        if gen11.len() != 34
            || gen11[..6] != [0x7a00_0004, 0x2034_4c1c, 0xd0, 0, 0, 0]
            || gen11[12..14] != [0x7a00_0004, 0x1014_1021]
            || gen11[18..] != want9[24..]
        {
            return TestResult::Fail(
                "Gen11 adds the command / tile cache bits, no null PIPE_CONTROL",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_legacy_request_stream_follows_linux
    );

    /// gen8_csb_parse: idle→active and preempted promote; everything else
    /// completes the active port 0.
    fn smoke_gen8_csb_step() -> TestResult {
        let e = |lower: u32| CsbEntry { lower, upper: 0 };
        if gen8_csb_step(&e(GEN8_CSB_IDLE_ACTIVE), false) != CsbStep::Promote
            || gen8_csb_step(&e(GEN8_CSB_PREEMPTED | 1 << 15), true) != CsbStep::Preempt
            || gen8_csb_step(&e(GEN8_CSB_PREEMPTED), false) != CsbStep::Promote
            || gen8_csb_step(&e(1 << 4 | 1 << 2), true) != CsbStep::Complete
            || gen8_csb_step(&e(1 << 4 | 1 << 3), true) != CsbStep::Complete
            || gen8_csb_step(&e(1 << 4 | 1 << 3), false) != CsbStep::Nop
        {
            return TestResult::Fail("Gen8 CSB classification");
        }
        if !gen8_csb(crate::intel_gpu::Generation::Skylake)
            || !gen8_csb(crate::intel_gpu::Generation::IceLake)
            || gen8_csb(crate::intel_gpu::Generation::TigerLake)
            || !uses_submit_queue(crate::intel_gpu::Generation::IceLake)
            || uses_submit_queue(crate::intel_gpu::Generation::Skylake)
        {
            return TestResult::Fail("CSB format and port write per generation");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rcs", smoke_gen8_csb_step);

    /// Gen11 loads ports through RING_EXECLIST_SQ_CONTENTS + EL_CTRL_LOAD,
    /// never the legacy ELSP.
    fn smoke_gen11_ports_load_through_submit_queue() -> TestResult {
        let (mut engine, hw) =
            make_engine_for_generation(crate::intel_gpu::Generation::IceLake).unwrap();
        let ctx = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(ctx, batch).unwrap();
        let writes: Vec<(u64, u32)> = hw
            .regs
            .writes
            .borrow()
            .iter()
            .filter(|(o, _)| (0x2510..0x2520).contains(o) || *o == 0x2550 || *o == RING_ELSP)
            .copied()
            .collect();
        let regs: Vec<u64> = writes.iter().map(|w| w.0).collect();
        if regs != [0x2518, 0x251c, 0x2510, 0x2514, 0x2550]
            || writes[0].1 != 0
            || writes[1].1 != 0
            || writes[4].1 != 1
        {
            return TestResult::Fail("Gen11 port write order");
        }
        let desc = (writes[3].1 as u64) << 32 | writes[2].1 as u64;
        if descriptor_sw_id(desc) != 1 || descriptor_lrca(desc) == 0 {
            return TestResult::Fail("Gen11 port 0 descriptor");
        }
        drop(hw);
        // SAFETY: the model never ran; nothing else references it.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen11_ports_load_through_submit_queue
    );

    /// Ports are only loaded into an idle Gen9 engine, completions retire
    /// in port order, and a stale (still all-ones) entry waits for the next
    /// poll.
    fn smoke_gen9_ports_load_only_when_idle() -> TestResult {
        let (mut engine, mut hw) =
            make_engine_for_generation(crate::intel_gpu::Generation::Skylake).unwrap();
        engine.reset_csb_pointers().unwrap();
        hw.write_ptr = GEN9_CSB_ENTRIES - 1;
        if hw.regs.writes_to(RCS0_SPEC.context_status_ptr()) != [0xffff_0505, 0xffff_0505]
            || engine
                .status
                .read32(csb_write_byte(crate::intel_gpu::Generation::Skylake))
                != 5
            || engine.status.read32(CSB_BUF_BYTE) != u32::MAX
        {
            return TestResult::Fail("reset_csb_pointers");
        }
        let a = engine.create_context().unwrap();
        let b = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(a, batch).unwrap();
        let elsp = hw.regs.writes_to(RING_ELSP);
        let port0 = (elsp[2] as u64) << 32 | elsp[3] as u64;
        // The write pointer moves before the entry lands.
        engine
            .status
            .write32(csb_write_byte(crate::intel_gpu::Generation::Skylake), 0);
        if !engine.poll_completions().is_empty() || engine.csb_head != 5 {
            return TestResult::Fail("an unwritten entry must wait");
        }
        hw.write_ptr = 5;
        hw.inject_csb(CsbEntry {
            lower: GEN8_CSB_IDLE_ACTIVE,
            upper: (port0 >> 32) as u32,
        });
        if !engine.poll_completions().is_empty()
            || engine.active[0].is_none()
            || engine.status.read32(CSB_BUF_BYTE) != u32::MAX
        {
            return TestResult::Fail("promote consumes its entry");
        }
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(b, batch).unwrap();
        if hw.regs.writes_to(RING_ELSP).len() != 4 {
            return TestResult::Fail("a busy Gen9 engine must not be reloaded");
        }
        hw.execute(port0);
        hw.inject_csb(CsbEntry {
            lower: 1 << 4 | 1 << 3,
            upper: (port0 >> 32) as u32,
        });
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != a || hw.regs.writes_to(RING_ELSP).len() != 8 {
            return TestResult::Fail("completion retires port 0 and loads the next context");
        }
        hw.consumed_elsp = 4;
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != b || !engine.is_idle() || engine.spurious_csb() != 0 {
            return TestResult::Fail("second context retires");
        }
        // SAFETY: every modelled request completed.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen9_ports_load_only_when_idle
    );

    /// A full timeslice with a waiter pauses the rings and reloads the busy
    /// engine with the waiter first. The switched-out context stops at its
    /// breadcrumb busywait, the PREEMPTED promotion unpauses, and both
    /// contexts then retire in their new order.
    fn smoke_gen9_timeslice_rotates_contexts() -> TestResult {
        let skl = crate::intel_gpu::Generation::Skylake;
        let (mut engine, mut hw) = make_engine_for_generation(skl).unwrap();
        engine.reset_csb_pointers().unwrap();
        hw.write_ptr = GEN9_CSB_ENTRIES - 1;
        let a = engine.create_context().unwrap();
        let b = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(a, batch).unwrap();
        let elsp = hw.regs.writes_to(RING_ELSP);
        let port_a = (elsp[2] as u64) << 32 | elsp[3] as u64;
        hw.inject_csb(CsbEntry {
            lower: GEN8_CSB_IDLE_ACTIVE,
            upper: (port_a >> 32) as u32,
        });
        engine.poll_completions();
        // Alone, ELSP[0] is never sliced.
        if engine.timeslice(0) || engine.timeslice(10 * TIMESLICE_NS) {
            return TestResult::Fail("no waiter, no timeslice");
        }
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(b, batch).unwrap();
        if engine.timeslice(20 * TIMESLICE_NS)
            || engine.timeslice(21 * TIMESLICE_NS - 1)
            || hw.regs.writes_to(RING_ELSP).len() != 4
        {
            return TestResult::Fail("the slice runs its full duration");
        }
        if !engine.timeslice(21 * TIMESLICE_NS)
            || engine.status.read32(HWS_PREEMPT_BYTE) != 1
            || engine.timeslice(30 * TIMESLICE_NS)
        {
            return TestResult::Fail("an expired slice pauses and reloads once");
        }
        let elsp = hw.regs.writes_to(RING_ELSP);
        let port1 = (elsp[4] as u64) << 32 | elsp[5] as u64;
        let port_b = (elsp[6] as u64) << 32 | elsp[7] as u64;
        if elsp.len() != 8 || port1 != port_a || port_b == port_a {
            return TestResult::Fail("the waiter takes ELSP[0], the sliced context ELSP[1]");
        }
        // A runs into its paused breadcrumb and stops there; a submission to
        // it is refused while it is loaded.
        hw.execute(port_a);
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        if !matches!(engine.submit(a, batch), Err(SubmitError::ContextBusy)) {
            return TestResult::Fail("a context under a timeslice stays covered");
        }
        hw.inject_csb(CsbEntry {
            lower: GEN8_CSB_PREEMPTED,
            upper: (port_b >> 32) as u32,
        });
        if !engine.poll_completions().is_empty()
            || engine.status.read32(HWS_PREEMPT_BYTE) != 0
            || engine.active[0].is_none()
            || engine.active[1].is_none()
        {
            return TestResult::Fail("the promotion unpauses without retiring");
        }
        hw.execute(port_b);
        hw.inject_csb(CsbEntry {
            lower: 1 << 4 | 1 << 3,
            upper: (port_b >> 32) as u32,
        });
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != b {
            return TestResult::Fail("the waiter retires first");
        }
        // A resumes from the busywait, now released, to its tail.
        hw.execute(port_a);
        hw.inject_csb(CsbEntry {
            lower: 1 << 4,
            upper: (port_a >> 32) as u32,
        });
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].ctx != a || engine.spurious_csb() != 0 {
            return TestResult::Fail("the sliced context retires after resuming");
        }
        // SAFETY: every modelled request completed.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen9_timeslice_rotates_contexts
    );

    /// An engine reset for an overdue request blames its context even when
    /// another context holds ELSP[0]; ELSP[0]'s request is requeued.
    fn smoke_gen9_reset_blames_the_overdue_request() -> TestResult {
        let skl = crate::intel_gpu::Generation::Skylake;
        let (mut engine, mut hw) = make_engine_for_generation(skl).unwrap();
        engine.reset_csb_pointers().unwrap();
        hw.write_ptr = GEN9_CSB_ENTRIES - 1;
        let a = engine.create_context().unwrap();
        let b = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        let ra = engine.submit(a, batch).unwrap();
        let elsp = hw.regs.writes_to(RING_ELSP);
        let port_a = (elsp[2] as u64) << 32 | elsp[3] as u64;
        hw.inject_csb(CsbEntry {
            lower: GEN8_CSB_IDLE_ACTIVE,
            upper: (port_a >> 32) as u32,
        });
        engine.poll_completions();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        let rb = engine.submit(b, batch).unwrap();
        // SAFETY: the model runs nothing; this stands for a completed reset.
        let (guilty, failed) = unsafe { engine.reset_rewind_blaming(Some(rb)) }.unwrap();
        if guilty != Some(b) || failed != [rb] {
            return TestResult::Fail("the overdue request's context is guilty");
        }
        let elsp = hw.regs.writes_to(RING_ELSP);
        let reloaded = (elsp[elsp.len() - 2] as u64) << 32 | elsp[elsp.len() - 1] as u64;
        if reloaded != port_a || ra == rb {
            return TestResult::Fail("ELSP[0]'s innocent request is reloaded");
        }
        // SAFETY: the model never ran a request.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_gen9_reset_blames_the_overdue_request
    );

    /// Resident batches take the Gen8 PTE format on Gen9/Gen11 and refuse
    /// the Gen12 one; context setup words precede the first request.
    fn smoke_legacy_resident_batch_and_context_setup() -> TestResult {
        for generation in [
            crate::intel_gpu::Generation::Skylake,
            crate::intel_gpu::Generation::IceLake,
        ] {
            let (mut engine, mut hw) = make_engine_for_generation(generation).unwrap();
            let ctx = engine.create_context().unwrap();
            let (wrong, _) = resident_fixture_with(&mut hw, crate::intel_gpu_gtt::PteFormat::Gen12);
            if engine.submit_resident(ctx, wrong).err() != Some(SubmitError::NoEngine) {
                return TestResult::Fail("a Gen12-format PPGTT is not a Gen9/Gen11 batch");
            }
            if engine
                .emit_context_setup(ctx, &[0x2200_0001, 0x7004, 0x0042_0042, 0])
                .is_err()
                || engine.emit_context_setup(ctx, &[0]).is_ok()
            {
                return TestResult::Fail("context setup accepts even-length words");
            }
            let (batch, weak) =
                resident_fixture_with(&mut hw, crate::intel_gpu_gtt::PteFormat::Gen8);
            let submission = engine.submit_resident(ctx, batch).unwrap();
            if engine.emit_context_setup(ctx, &[0, 0]) != Err(SubmitError::ContextBusy) {
                return TestResult::Fail("setup only lands ahead of the next request");
            }
            let context = engine.context(ctx).unwrap();
            if context.ring_mem.read32(4) != 0x7004 || context.ring_mem.read32(16) != 0x7a00_0004 {
                return TestResult::Fail("setup words precede the request");
            }
            hw.step();
            let done = engine.poll_completions();
            if done.len() != 1
                || submission.fence.result() != Some(Ok(()))
                || weak.upgrade().is_some()
            {
                return TestResult::Fail("Gen8-format resident batch completes");
            }
            // SAFETY: every modelled request completed.
            unsafe {
                engine.release_after_reset();
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_legacy_resident_batch_and_context_setup
    );

    /// A fresh Gen9/Gen11 context loads with restore inhibited and clears it
    /// after its first save; Gen9 contexts point at the engine's indirect
    /// workaround batch. Gen12 is untouched.
    fn smoke_legacy_context_restore_inhibit_and_wa_bb() -> TestResult {
        let control = REG_STATE_PAGE_BYTE + ((CTX_CONTEXT_CONTROL + 1) as u64) * 4;
        let indirect = REG_STATE_PAGE_BYTE + ((GEN11_CTX_RCS_INDIRECT_CTX + 1) as u64) * 4;
        let skl = crate::intel_gpu::Generation::Skylake;
        let (mut engine, mut hw) = make_engine_for_generation(skl).unwrap();
        engine.install_gen9_wa_bb().unwrap();
        let (bb, bytes) = match &engine.wa_bb {
            Some((_, bb, bytes)) => (bb.ggtt_offset(), *bytes),
            None => return TestResult::Fail("Gen9 RCS installs its WA batch"),
        };
        let ctx = engine.create_context().unwrap();
        let image = &engine.context(ctx).unwrap().image;
        if image.read32(control) != ctx_control_value(skl) | 1
            || image.read32(indirect) != bb | (bytes / 64)
            || bytes % 64 != 0
        {
            return TestResult::Fail("restore inhibit and the indirect WA pointer");
        }
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        engine.submit(ctx, batch).unwrap();
        hw.step();
        if engine.poll_completions().len() != 1
            || engine.context(ctx).unwrap().image.read32(control) != ctx_control_value(skl)
        {
            return TestResult::Fail("first retirement clears restore inhibit");
        }
        // SAFETY: every modelled request completed.
        unsafe {
            engine.release_after_reset();
        }
        let (mut engine, _hw) = make_engine().unwrap();
        engine.install_gen9_wa_bb().unwrap();
        let ctx = engine.create_context().unwrap();
        if engine.wa_bb.is_some()
            || engine.context(ctx).unwrap().image.read32(control) != CTX_CONTROL_VALUE
        {
            return TestResult::Fail("Gen12 keeps its template");
        }
        // SAFETY: nothing was submitted.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_legacy_context_restore_inhibit_and_wa_bb
    );

    /// `__engines_record_defaults`: Gen9 runs the context setup and the null
    /// render state on a restore-inhibited context, records the saved image,
    /// and later contexts start from it (status page cleared, register state
    /// rewritten, restore not inhibited). Gen11 records with an empty batch;
    /// Gen12 has no default image.
    fn smoke_legacy_default_image_seeds_new_contexts() -> TestResult {
        let control = REG_STATE_PAGE_BYTE + ((CTX_CONTEXT_CONTROL + 1) as u64) * 4;
        let indirect = REG_STATE_PAGE_BYTE + ((GEN11_CTX_RCS_INDIRECT_CTX + 1) as u64) * 4;
        let start = REG_STATE_PAGE_BYTE + ((CTX_RING_BUFFER_START + 1) as u64) * 4;
        let skl = crate::intel_gpu::Generation::Skylake;
        let (mut engine, mut hw) = make_engine_for_generation(skl).unwrap();
        engine.install_gen9_wa_bb().unwrap();
        let live = engine.live_allocations();
        let setup = [mi_load_register_imm(1, false), 0x7004, 0x0001_0001, MI_NOOP];
        let (golden, request) = engine.begin_default_image(&setup).unwrap();
        if engine.finish_default_image(golden) != Err(SubmitError::ContextBusy) {
            return TestResult::Fail("the image is recorded only after it retires");
        }
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].request != request {
            return TestResult::Fail("the golden request retires");
        }
        // The null render state ran: 84 GFXPIPE commands.
        let saved = SAVED_3D_MARKER | 84;
        if engine.context(golden).unwrap().image.read32(SAVED_3D_BYTE) != saved {
            return TestResult::Fail("Gen9 golden batch is the null render state");
        }
        engine.finish_default_image(golden).unwrap();
        if engine.context(golden).is_ok()
            || !engine.has_default_image()
            || engine.live_allocations() != live + 1
            || engine.begin_default_image(&setup) != Err(SubmitError::NoEngine)
        {
            return TestResult::Fail("one default image replaces the golden context");
        }
        let ctx = engine.create_context().unwrap();
        let image = &engine.context(ctx).unwrap().image;
        let ring = engine.context(ctx).unwrap().ring_mem.ggtt_offset();
        let (bb, bytes) = match &engine.wa_bb {
            Some((_, bb, bytes)) => (bb.ggtt_offset(), *bytes),
            None => return TestResult::Fail("Gen9 RCS installs its WA batch"),
        };
        if image.read32(SAVED_3D_BYTE) != saved
            || image.read32(control) != ctx_control_value(skl)
            || image.read32(indirect) != bb | (bytes / 64)
            || image.read32(start) != ring
            || (0..GTT_PAGE_SIZE)
                .step_by(4)
                .any(|at| image.read32(at) != 0)
            || !engine.context(ctx).unwrap().restore_valid
        {
            return TestResult::Fail("new contexts start from the default image");
        }
        // SAFETY: every modelled request completed.
        unsafe {
            engine.release_after_reset();
        }
        let icl = crate::intel_gpu::Generation::IceLake;
        let (mut engine, mut hw) = make_engine_for_generation(icl).unwrap();
        let (golden, _) = engine.begin_default_image(&setup).unwrap();
        hw.step();
        let _ = engine.poll_completions();
        let empty = engine.context(golden).unwrap().image.read32(SAVED_3D_BYTE) == 0;
        let recorded = engine.finish_default_image(golden).is_ok();
        let ctx = engine.create_context().unwrap();
        if !empty || !recorded || engine.context(ctx).unwrap().image.read32(control) & 1 != 0 {
            return TestResult::Fail("Gen11 records an empty-batch default image");
        }
        // SAFETY: every modelled request completed.
        unsafe {
            engine.release_after_reset();
        }
        let (mut engine, _hw) = make_engine().unwrap();
        if engine.begin_default_image(&setup) != Err(SubmitError::NoEngine) {
            return TestResult::Fail("Gen12 records no default image");
        }
        // SAFETY: nothing was submitted.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_legacy_default_image_seeds_new_contexts
    );

    /// An engine reset with context A hung on port 0 and context B queued
    /// behind it: A's request fails with Hang and its batch is released, B
    /// is loaded again, the status page address and CSB pointers are
    /// restored, and B then completes.
    fn smoke_legacy_engine_reset_rewinds_innocent_requests() -> TestResult {
        let skl = crate::intel_gpu::Generation::Skylake;
        let (mut engine, mut hw) = make_engine_for_generation(skl).unwrap();
        let a = engine.create_context().unwrap();
        let b = engine.create_context().unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        let hung = engine.submit(a, batch).unwrap();
        let batch = engine.write_batch(&[MI_BATCH_BUFFER_END]).unwrap();
        let innocent = engine.submit(b, batch).unwrap();
        let hung_fence = engine
            .inflight
            .iter()
            .find(|r| r.id == hung)
            .map(|r| r.fence.clone())
            .unwrap();
        let live = engine.live_allocations();
        // The hardware never completes A. Reset the engine alone.
        let elsp_before = hw.regs.writes_to(engine.spec().elsp()).len();
        // The hardware took A's submission and never completed it.
        hw.consumed_elsp = elsp_before;
        // SAFETY: the modelled engine was reset and runs nothing.
        let (guilty, failed) = unsafe { engine.reset_rewind() }.unwrap();
        if guilty != Some(a) || failed != alloc::vec![hung] {
            return TestResult::Fail("the port-0 context is the guilty one");
        }
        if hung_fence.result() != Some(Err(JobError::Hang)) || engine.live_allocations() != live - 1
        {
            return TestResult::Fail("the hung request fails and releases its batch");
        }
        if hw.regs.writes_to(engine.spec().hws_pga()).last() != Some(&engine.status_ggtt())
            || hw.regs.writes_to(engine.spec().elsp()).len() == elsp_before
        {
            return TestResult::Fail("HWS_PGA restored and the innocent context reloaded");
        }
        // The reset also rewound the hardware's CSB write pointer.
        hw.write_ptr = csb_entries(skl) - 1;
        hw.step();
        let done = engine.poll_completions();
        if done.len() != 1 || done[0].request != innocent || !engine.is_idle() {
            return TestResult::Fail("the innocent request completes after the reset");
        }
        engine.destroy_context(a).unwrap();
        // SAFETY: every modelled request completed.
        unsafe {
            engine.release_after_reset();
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rcs",
        smoke_legacy_engine_reset_rewinds_innocent_requests
    );
}
