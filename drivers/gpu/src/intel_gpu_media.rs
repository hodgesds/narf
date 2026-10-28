//! Media engines — VCS / VECS execlists submission (#1022,
//! Intel GPU queue lane Q12).
//!
//! The render engine (RCS0, #1011) landed with the full
//! execlists submission machinery in [`crate::intel_gpu_rcs`]:
//! context images, rings, ELSP doorbells, CSB completion
//! drain. The media engines — the video command streamers
//! (VCS, Intel's BSD rings) and the video enhancement command
//! streamer (VECS, the VEBox ring) — run the *same* protocol
//! on different register blocks. This module instantiates the
//! shared machinery per media engine; it does not fork it.
//! What is media-specific lives here:
//!
//! - the engine table ([`GEN12_MEDIA_ENGINES`]): register
//!   bases, descriptor class/instance, image bound;
//! - the Gen11 media forcewake sub-domains (per-VDBox /
//!   per-VEBox), which gate the media register blocks;
//! - production glue mirroring `intel_gpu_rcs::submit_dwords`,
//!   with submissions wrapped in the engine's sub-domain hold;
//! - VA-batch submission through the shared
//!   [`RcsEngine::submit_ppgtt`] (added by this lane).
//!
//! ## Engine set (Gen12 Xe-LP)
//!
//! | Engine | Base       | Class (descriptor) | Instance | i915 name |
//! |--------|------------|--------------------|----------|-----------|
//! | VCS0   | `0x1c0000` | VideoDecode (1)    | 0        | BSD       |
//! | VCS1   | `0x1c4000` | VideoDecode (1)    | 1        | BSD2      |
//! | VECS0  | `0x1c8000` | VideoEnhance (2)   | 0        | VEBox     |
//!
//! Bases are the Gen11+ media ring bases (i915
//! `intel_gt_regs.h`: `GEN11_BSD_RING_BASE`,
//! `GEN11_BSD2_RING_BASE`, `GEN11_VEBOX_RING_BASE`), confirmed
//! against the v5.10 `i915_reg.h` the RCS lane cross-checked —
//! the Gen11 media block interleaves engines in 0x4000 slots
//! (VCS0, VCS1, VECS0, then VCS2/VCS3/VECS1 at 0x1d0000+ on
//! wider parts; Xe-LP ships the first three). The engine set
//! per generation comes from the i915 engine table
//! (`intel_engine_cs.c`, engines with a `graphics_ver` 11 base)
//! restricted to the Xe-LP media configuration. Per-SKU
//! *fusing* (a part with VCS1 fused off, say) is not modelled:
//! the fuse readout is a first-silicon step, named in the
//! remainders below.
//!
//! ## Context images
//!
//! The media register-state template is the shared PRM ENGINE
//! CONTEXT layout at the engine's own base, minus the
//! render-only `R_PWR_CLK_STATE` group — i915's Gen12 XCS
//! offset table (`intel_lrc.c gen12_xcs_offsets`) has no third
//! group, and its register-state writer programs
//! `CTX_R_PWR_CLK_STATE` only for render-class contexts. The
//! hardware context image for non-render engines is
//! `GEN8_LR_CONTEXT_OTHER_SIZE` = 2 pages in i915's
//! `intel_engine_context_size`; [`MEDIA_IMAGE_PAGES`] = 4 is
//! the allocation bound above it, under the same oversizing
//! argument as the RCS bound (hardware touches only its own
//! image span; undersizing would corrupt).
//!
//! ## Forcewake
//!
//! Media register blocks sit behind per-engine forcewake
//! sub-domains on Gen11+: `FORCEWAKE_MEDIA_VDBOX_GEN11(n)` at
//! `0xa540 + 4n` with ack at `0x0d50 + 4n`, and
//! `FORCEWAKE_MEDIA_VEBOX_GEN11(n)` at `0xa560 + 4n` with ack
//! at `0x0d70 + 4n` (i915 `i915_reg.h`). i915 takes the
//! engine's sub-domain hold for the lifetime of a pinned
//! context (`intel_lrc.c` context pin); this driver takes it
//! around the MMIO-touching operations instead — engine
//! bring-up (`RING_HWS_PGA`) and submission (the ELSP
//! doorbell is rung inside `submit`'s pump). Completion
//! polling touches no MMIO (the CSB lives in host memory), so
//! it takes no hold, mirroring the split the aggregate-domain
//! manager documents.
//!
//! The masked-write protocol, poll budget, re-kick and
//! rollback discipline mirror the aggregate forcewake domains
//! (render / blitter / media) of the forcewake lane (#1013,
//! PR #1112, unmerged at the time of writing): those domains
//! live in that lane's module, so the sub-domain manager here
//! is a sibling implementation of the same discipline, not a
//! copy of its code. Composition: when #1112 lands, the
//! aggregate MEDIA domain hold composes *outside* the
//! sub-domain hold at the marked seam in
//! [`submit_media_dwords`] — i915 nests the per-engine
//! VDBox/VEBox domains inside the media well the same way.
//!
//! ## Reporting
//!
//! [`media_engines_for`] is the inventory surface: the probe
//! path announces the media engines a probed Gen12 part
//! carries, and the DRM layer can consume the same list. No
//! engine-query UAPI exists in the tree today (the Intel DRM
//! card is identity-only), so nothing is advertised to
//! userspace beyond the probe announce until such a UAPI
//! lands — the inventory is deliberately the exact set the
//! submission path can drive, no wider.
//!
//! ## Remainders (named, not silently absent)
//!
//! - Per-SKU fusing: engines fused off on a given part are
//!   still listed; the media fuse readout that would trim
//!   the table is first-silicon work.
//! - BCS0 (copy engine, base 0x22000) and any compute
//!   engines: the shared machinery takes them via one more
//!   `EngineSpec` each, but this lane's scope is the media
//!   engines; BCS is a follow-on.
//! - MTL / PTL media: the Xe-LPG GT is a different engine
//!   generation (GuC-era submission); `media_engines_for`
//!   returns engines only for the Gen12 region generation.
//! - Codec programming itself (VDBox bitstream control,
//!   SFC) sits above submission, with the future media
//!   userspace; this lane delivers the engines, contexts and
//!   the submission conversation.

use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_rcs::{
    production_arena, BarWindow, CompletedRequest, ContextId, EngineClass, EngineSpec, RcsEngine,
    SharedArena, SubmitError,
};
use crate::intel_gpu_regions::RegionGeneration;

// ── Engine table ────────────────────────────────────────────────

/// VCS0 register block base (i915 `GEN11_BSD_RING_BASE`).
pub const VCS0_BASE: u64 = 0x1C_0000;
/// VCS1 register block base (i915 `GEN11_BSD2_RING_BASE`).
pub const VCS1_BASE: u64 = 0x1C_4000;
/// VECS0 register block base (i915 `GEN11_VEBOX_RING_BASE`).
pub const VECS0_BASE: u64 = 0x1C_8000;

/// Pages allocated per media context image: an allocation
/// bound above the 2-page non-render hardware image (i915
/// `GEN8_LR_CONTEXT_OTHER_SIZE`). Flagged for first-silicon
/// verification with the same status as the RCS bound.
pub const MEDIA_IMAGE_PAGES: u32 = 4;

/// VCS0: video-decode class, instance 0.
pub const VCS0_SPEC: EngineSpec = EngineSpec {
    name: "vcs0",
    class: EngineClass::VideoDecode,
    instance: 0,
    base: VCS0_BASE,
    image_pages: MEDIA_IMAGE_PAGES,
};
/// VCS1: video-decode class, instance 1.
pub const VCS1_SPEC: EngineSpec = EngineSpec {
    name: "vcs1",
    class: EngineClass::VideoDecode,
    instance: 1,
    base: VCS1_BASE,
    image_pages: MEDIA_IMAGE_PAGES,
};
/// VECS0: video-enhancement class, instance 0.
pub const VECS0_SPEC: EngineSpec = EngineSpec {
    name: "vecs0",
    class: EngineClass::VideoEnhance,
    instance: 0,
    base: VECS0_BASE,
    image_pages: MEDIA_IMAGE_PAGES,
};

/// The media engines of the Gen12 (Xe-LP) GT, in instance
/// order.
pub const GEN12_MEDIA_ENGINES: [EngineSpec; 3] = [VCS0_SPEC, VCS1_SPEC, VECS0_SPEC];

/// The media engines a region generation carries. Only Gen12
/// is served: the Xe-LPG GT is a different engine generation
/// (GuC-era submission) that this execlists module does not
/// drive, so XeLpg carries no engines here — the empty set is
/// the honest inventory, and both callers are built for it
/// (probe skips the announce; attach refuses `NoEngine`).
/// Panther Lake has no [`RegionGeneration`] at all
/// (`Generation::region_generation` returns `None` for it), so
/// it can never be asked about. When a generation's real media
/// set lands, it goes here, not in a second table somewhere
/// else.
pub fn media_engines_for(gen: RegionGeneration) -> &'static [EngineSpec] {
    match gen {
        RegionGeneration::Gen12 => &GEN12_MEDIA_ENGINES,
        RegionGeneration::XeLpg => &[],
    }
}

/// A media engine selector for the production entry points.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaEngineId {
    /// First video command streamer.
    Vcs0,
    /// Second video command streamer.
    Vcs1,
    /// Video enhancement command streamer.
    Vecs0,
}

impl MediaEngineId {
    /// Every media engine, in table order.
    pub const ALL: [MediaEngineId; 3] = [Self::Vcs0, Self::Vcs1, Self::Vecs0];
    /// The engine's identity.
    pub const fn spec(self) -> EngineSpec {
        match self {
            MediaEngineId::Vcs0 => VCS0_SPEC,
            MediaEngineId::Vcs1 => VCS1_SPEC,
            MediaEngineId::Vecs0 => VECS0_SPEC,
        }
    }
}

// ── Media forcewake sub-domains (Gen11+) ────────────────────────

/// `FORCEWAKE_MEDIA_VDBOX_GEN11(0)` — per-VDBox request
/// registers stride 4 bytes from here (i915 `i915_reg.h`).
pub const FORCEWAKE_MEDIA_VDBOX_BASE: u64 = 0xA540;
/// `FORCEWAKE_MEDIA_VEBOX_GEN11(0)`.
pub const FORCEWAKE_MEDIA_VEBOX_BASE: u64 = 0xA560;
/// `FORCEWAKE_ACK_MEDIA_VDBOX_GEN11(0)`.
pub const FORCEWAKE_ACK_MEDIA_VDBOX_BASE: u64 = 0x0D50;
/// `FORCEWAKE_ACK_MEDIA_VEBOX_GEN11(0)`.
pub const FORCEWAKE_ACK_MEDIA_VEBOX_BASE: u64 = 0x0D70;
/// The kernel (driver) forcewake request bit — the only bit
/// this driver ever requests, as with the aggregate domains.
pub const FORCEWAKE_KERNEL: u32 = 1 << 0;
/// Poll budget for a forcewake ack transition. Mirrors the
/// aggregate domains' budget: a generous multiple of i915's
/// ~50 ms force-wake wait at register-read speed; expiry is a
/// typed refusal, never a hang.
pub const MEDIA_FW_ACK_POLL_BUDGET: u32 = 100_000;

/// Masked-write encoding to *set* `v`'s bits in a forcewake
/// register: the mask rides in the upper halfword.
const fn fw_masked_enable(v: u32) -> u32 {
    v | (v << 16)
}
/// Masked-write encoding to *clear* `v`'s bits.
const fn fw_masked_disable(v: u32) -> u32 {
    v << 16
}

/// One Gen11 media forcewake sub-domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaFwDomain {
    /// The VDBox domain gating VCS instance `n`'s block.
    VdBox(u8),
    /// The VEBox domain gating VECS instance `n`'s block.
    VeBox(u8),
}

impl MediaFwDomain {
    /// The sub-domain gating `spec`'s register block, if the
    /// engine class has one (media classes only).
    pub fn of(spec: &EngineSpec) -> Option<MediaFwDomain> {
        match spec.class {
            EngineClass::VideoDecode => Some(MediaFwDomain::VdBox(spec.instance)),
            EngineClass::VideoEnhance => Some(MediaFwDomain::VeBox(spec.instance)),
            _ => None,
        }
    }
    /// The domain's request register.
    pub const fn set_reg(self) -> u64 {
        match self {
            MediaFwDomain::VdBox(n) => FORCEWAKE_MEDIA_VDBOX_BASE + 4 * (n as u64),
            MediaFwDomain::VeBox(n) => FORCEWAKE_MEDIA_VEBOX_BASE + 4 * (n as u64),
        }
    }
    /// The domain's ack register.
    pub const fn ack_reg(self) -> u64 {
        match self {
            MediaFwDomain::VdBox(n) => FORCEWAKE_ACK_MEDIA_VDBOX_BASE + 4 * (n as u64),
            MediaFwDomain::VeBox(n) => FORCEWAKE_ACK_MEDIA_VEBOX_BASE + 4 * (n as u64),
        }
    }
    /// Slot in the manager's refcount table. Slots 0..2 are
    /// VDBox instances, 2..4 VEBox instances — the manager's
    /// table is sized for the Gen11 sub-domain space this
    /// driver can name, not just the three Gen12 engines.
    const fn slot(self) -> usize {
        match self {
            MediaFwDomain::VdBox(n) => n as usize,
            MediaFwDomain::VeBox(n) => 2 + n as usize,
        }
    }
}

/// Failure modes of a media forcewake hold.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MediaFwError {
    /// The ack never set after a request (and one re-kick);
    /// the request was rolled back, no hold is held.
    AckTimeout {
        /// Domain whose ack never arrived.
        domain: MediaFwDomain,
    },
    /// The ack never cleared after the last release. The hold
    /// itself is dropped; the domain may stay awake.
    AckClearTimeout {
        /// Domain whose ack never cleared.
        domain: MediaFwDomain,
    },
    /// Release without a matching acquire.
    NotHeld {
        /// Domain released without a hold.
        domain: MediaFwDomain,
    },
    /// The hold refcount would overflow.
    RefcountOverflow {
        /// Domain whose refcount overflowed.
        domain: MediaFwDomain,
    },
}

/// Refcounted media forcewake sub-domain holds. Owns no MMIO
/// window — every operation takes the caller's window, the
/// same seam the aggregate-domain manager uses.
#[derive(Debug)]
pub struct MediaForcewake {
    counts: [u32; 4],
}

impl Default for MediaForcewake {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaForcewake {
    /// A manager with no holds.
    pub const fn new() -> Self {
        Self { counts: [0; 4] }
    }

    /// Current hold count on `domain`.
    pub fn held(&self, domain: MediaFwDomain) -> u32 {
        self.counts[domain.slot()]
    }

    /// Poll the domain's ack until it reaches `want_set` or
    /// the budget expires.
    fn wait_ack<M: MmioWindow>(&self, mmio: &M, domain: MediaFwDomain, want_set: bool) -> bool {
        let mut polls = 0u32;
        loop {
            let acked = mmio.read32(domain.ack_reg()) & FORCEWAKE_KERNEL != 0;
            if acked == want_set {
                return true;
            }
            polls += 1;
            if polls >= MEDIA_FW_ACK_POLL_BUDGET {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    /// Acquire a hold on `domain`. Only the 0→1 transition
    /// programs hardware; nested acquires just count. On ack
    /// timeout the request is kicked once (clear, then set)
    /// and finally rolled back — a failed acquire holds
    /// nothing.
    pub fn acquire<M: MmioWindow>(
        &mut self,
        mmio: &M,
        domain: MediaFwDomain,
    ) -> Result<(), MediaFwError> {
        let slot = domain.slot();
        if self.counts[slot] > 0 {
            if self.counts[slot] == u32::MAX {
                return Err(MediaFwError::RefcountOverflow { domain });
            }
            self.counts[slot] += 1;
            return Ok(());
        }
        mmio.write32(domain.set_reg(), fw_masked_enable(FORCEWAKE_KERNEL));
        if !self.wait_ack(mmio, domain, true) {
            // The lost-ack quirk the aggregate domains also
            // handle: drop the request and re-assert it once
            // before concluding the domain is unresponsive.
            mmio.write32(domain.set_reg(), fw_masked_disable(FORCEWAKE_KERNEL));
            mmio.write32(domain.set_reg(), fw_masked_enable(FORCEWAKE_KERNEL));
            if !self.wait_ack(mmio, domain, true) {
                mmio.write32(domain.set_reg(), fw_masked_disable(FORCEWAKE_KERNEL));
                return Err(MediaFwError::AckTimeout { domain });
            }
        }
        self.counts[slot] = 1;
        Ok(())
    }

    /// Release a hold. Only the 1→0 transition programs
    /// hardware (immediate clear — the deferred clear i915
    /// uses is a host-side optimisation, not protocol).
    pub fn release<M: MmioWindow>(
        &mut self,
        mmio: &M,
        domain: MediaFwDomain,
    ) -> Result<(), MediaFwError> {
        let slot = domain.slot();
        if self.counts[slot] == 0 {
            return Err(MediaFwError::NotHeld { domain });
        }
        self.counts[slot] -= 1;
        if self.counts[slot] > 0 {
            return Ok(());
        }
        mmio.write32(domain.set_reg(), fw_masked_disable(FORCEWAKE_KERNEL));
        if !self.wait_ack(mmio, domain, false) {
            return Err(MediaFwError::AckClearTimeout { domain });
        }
        Ok(())
    }

    /// Reset every sub-domain (masked-clear all bits, no ack
    /// waits) and drop every hold count — the same shape as
    /// the aggregate manager's sanitize: used when the driver
    /// takes over a GT whose forcewake state it did not
    /// create.
    pub fn sanitize<M: MmioWindow>(&mut self, mmio: &M) {
        for domain in [
            MediaFwDomain::VdBox(0),
            MediaFwDomain::VdBox(1),
            MediaFwDomain::VeBox(0),
            MediaFwDomain::VeBox(1),
        ] {
            mmio.write32(domain.set_reg(), fw_masked_disable(0xFFFF));
        }
        self.counts = [0; 4];
    }
}

// ── Production glue ─────────────────────────────────────────────
//
// Mirrors the RCS glue in `intel_gpu_rcs`: the media engines
// attach lazily to the probed Gen12 controller, each with a
// default context, the first time a submission is asked for.
// All engines on the controller — RCS included — allocate
// from the one production arena
// (`intel_gpu_rcs::production_arena`), so context images,
// rings and batches never alias across engines.

/// Failure modes of the media production entry points.
#[derive(Debug)]
pub enum MediaError {
    /// The shared execlists submission path failed.
    Submit(SubmitError),
    /// A media forcewake sub-domain hold failed.
    Forcewake(MediaFwError),
}

impl From<SubmitError> for MediaError {
    fn from(e: SubmitError) -> Self {
        MediaError::Submit(e)
    }
}

impl From<MediaFwError> for MediaError {
    fn from(e: MediaFwError) -> Self {
        MediaError::Forcewake(e)
    }
}

type MediaProductionEngine = RcsEngine<BarWindow, SharedArena>;

struct MediaState {
    window: BarWindow,
    fw: MediaForcewake,
    engines: Vec<(EngineSpec, MediaProductionEngine, Option<ContextId>)>,
}

static MEDIA_STATE: narf_lib::sync::IrqSafeSpinLock<Option<MediaState>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn attach_media() -> Result<(), MediaError> {
    let built = crate::intel_gpu::with_controller(|gpu| {
        let rg = gpu.chip_info().generation.region_generation()?;
        let specs = media_engines_for(rg);
        if specs.is_empty() {
            return None;
        }
        let window = BarWindow::new(gpu.gtt_mmadr);
        let arena = production_arena(gpu.gtt_mmadr);
        let mut fw = MediaForcewake::new();
        let mut engines = Vec::new();
        for spec in specs {
            // Engine bring-up programs MMIO (RING_HWS_PGA), so
            // it runs inside the engine's sub-domain hold.
            let domain = MediaFwDomain::of(spec)?;
            fw.acquire(&window, domain).ok()?;
            let eng = RcsEngine::with_spec(*spec, BarWindow::new(gpu.gtt_mmadr), arena.clone());
            let _ = fw.release(&window, domain);
            engines.push((*spec, eng.ok()?, None));
        }
        Some(MediaState {
            window,
            fw,
            engines,
        })
    })
    .flatten()
    .ok_or(MediaError::Submit(SubmitError::NoEngine))?;
    *MEDIA_STATE.lock() = Some(built);
    Ok(())
}

/// Submit raw batch dwords on the default context of a media
/// engine of the probed Gen12 controller, attaching the media
/// engines on first use. Returns the engine-wide request id;
/// completion is observed through [`poll_media_completions`].
///
/// The submission runs inside the engine's forcewake
/// sub-domain hold (the ELSP doorbell is rung inside the
/// submit). Composition seam: once the aggregate forcewake
/// manager (#1013 / PR #1112) lands, its MEDIA domain hold is
/// acquired immediately before the sub-domain hold here and
/// released immediately after — the sub-domain hold nests
/// inside the aggregate media well, as in i915.
pub fn submit_media_dwords(engine: MediaEngineId, dwords: &[u32]) -> Result<u64, MediaError> {
    let mut guard = MEDIA_STATE.lock();
    if guard.is_none() {
        drop(guard);
        attach_media()?;
        guard = MEDIA_STATE.lock();
    }
    let state = guard.as_mut().expect("attached above");
    let spec = engine.spec();
    let domain = MediaFwDomain::of(&spec).ok_or(SubmitError::NoEngine)?;
    let idx = state
        .engines
        .iter()
        .position(|(s, _, _)| *s == spec)
        .ok_or(SubmitError::NoEngine)?;
    let (_, eng, ctx_slot) = &mut state.engines[idx];
    if ctx_slot.is_none() {
        *ctx_slot = Some(eng.create_context()?);
    }
    let ctx = ctx_slot.expect("created above");
    let batch = eng.write_batch(dwords)?;
    state.fw.acquire(&state.window, domain)?;
    let submitted = eng.submit(ctx, batch);
    let released = state.fw.release(&state.window, domain);
    match submitted {
        Ok(id) => {
            released?;
            Ok(id)
        }
        Err(e) => Err(MediaError::Submit(e)),
    }
}

/// Drain completions from one media engine, if attached.
/// Touches no MMIO (the CSB is host memory), so — like the
/// RCS poll path — it takes no forcewake hold.
pub fn poll_media_completions(engine: MediaEngineId) -> Vec<CompletedRequest> {
    let mut guard = MEDIA_STATE.lock();
    match guard.as_mut() {
        Some(state) => {
            let spec = engine.spec();
            match state.engines.iter_mut().find(|(s, _, _)| *s == spec) {
                Some((_, eng, _)) => eng.poll_completions(),
                None => Vec::new(),
            }
        }
        None => Vec::new(),
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the media engines. The fake hardware is a
    //! *model of the GPU media block*, not of the driver: each
    //! engine's fake watches its own ELSP offset, executes the
    //! loaded context's ring (following `MI_BATCH_BUFFER_START`
    //! in either address-space form), performs breadcrumbs,
    //! and posts Gen12 CSB entries into that engine's status
    //! page. All three engines share one register file and one
    //! GGTT object registry, exactly as on the real GT, so
    //! aliasing between engines is observable, not assumed
    //! away.

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::intel_gpu_rcs::{
        build_reg_state, build_reg_state_for, context_descriptor, context_descriptor_for,
        descriptor_class, descriptor_instance, descriptor_lrca, descriptor_sw_id,
        mi_load_register_imm, GpuAllocator, GpuBacking, BB_START_ASI_PPGTT, CSB_BUF_BYTE,
        CSB_ENTRIES, CSB_WRITE_BYTE, CTX_CONTEXT_CONTROL, CTX_END, CTX_LRI_HEADER_0,
        CTX_LRI_HEADER_2, CTX_PDP3_UDW, CTX_RING_BUFFER_START, CTX_R_PWR_CLK_STATE,
        GGTT_ARENA_BASE, GGTT_ARENA_PAGES, IDLE_SW_ID, MI_BATCH_BUFFER_END, RCS0_SPEC,
        REG_STATE_PAGE_BYTE, RING_BYTES,
    };

    // ── Fake MMIO (with forcewake ack modelling) ────────────

    #[derive(Clone)]
    struct FakeRegs {
        map: Rc<RefCell<BTreeMap<u64, u32>>>,
        writes: Rc<RefCell<Vec<(u64, u32)>>>,
        /// When false, forcewake acks never follow requests
        /// (the unresponsive-domain fixture knob).
        ack_enabled: Rc<RefCell<bool>>,
    }

    /// The ack register a forcewake *request* register drives,
    /// per the Gen11 sub-domain register layout.
    fn fw_ack_for_set(off: u64) -> Option<u64> {
        if (FORCEWAKE_MEDIA_VDBOX_BASE..FORCEWAKE_MEDIA_VDBOX_BASE + 8).contains(&off)
            && (off - FORCEWAKE_MEDIA_VDBOX_BASE) % 4 == 0
        {
            Some(FORCEWAKE_ACK_MEDIA_VDBOX_BASE + (off - FORCEWAKE_MEDIA_VDBOX_BASE))
        } else if (FORCEWAKE_MEDIA_VEBOX_BASE..FORCEWAKE_MEDIA_VEBOX_BASE + 8).contains(&off)
            && (off - FORCEWAKE_MEDIA_VEBOX_BASE) % 4 == 0
        {
            Some(FORCEWAKE_ACK_MEDIA_VEBOX_BASE + (off - FORCEWAKE_MEDIA_VEBOX_BASE))
        } else {
            None
        }
    }

    impl FakeRegs {
        fn new() -> Self {
            Self {
                map: Rc::new(RefCell::new(BTreeMap::new())),
                writes: Rc::new(RefCell::new(Vec::new())),
                ack_enabled: Rc::new(RefCell::new(true)),
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
        fn write_index(&self, off: u64, val: u32) -> Option<usize> {
            self.writes
                .borrow()
                .iter()
                .position(|(o, v)| *o == off && *v == val)
        }
    }

    impl MmioWindow for FakeRegs {
        fn read32(&self, off: u64) -> u32 {
            *self.map.borrow().get(&off).unwrap_or(&0)
        }
        fn write32(&self, off: u64, val: u32) {
            self.map.borrow_mut().insert(off, val);
            self.writes.borrow_mut().push((off, val));
            // Model the forcewake ack: the ack register follows
            // the masked request state, as the hardware's power
            // logic drives it once the domain wakes.
            if *self.ack_enabled.borrow() {
                if let Some(ack_off) = fw_ack_for_set(off) {
                    let mask = val >> 16;
                    let cur = *self.map.borrow().get(&ack_off).unwrap_or(&0);
                    let next = (cur & !mask) | (val & mask);
                    self.map.borrow_mut().insert(ack_off, next);
                }
            }
        }
    }

    // ── Fake backing + arena (mirrors the RCS fixtures) ─────

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

    /// Cloneable handle over the rig's one fake arena — the
    /// fixture form of production's `SharedArena`.
    #[derive(Clone)]
    struct SharedFakeArena(Rc<RefCell<FakeArena>>);

    impl GpuAllocator for SharedFakeArena {
        type Backing = FakeBacking;

        fn alloc(&mut self, pages: u32) -> Result<FakeBacking, SubmitError> {
            self.0.borrow_mut().alloc(pages)
        }
        fn free(&mut self, backing: FakeBacking) {
            self.0.borrow_mut().free(backing)
        }
        fn live_allocations(&self) -> usize {
            self.0.borrow().live_allocations()
        }
        fn live_pages(&self) -> u32 {
            self.0.borrow().live_pages()
        }
    }

    // ── Fake hardware (one per engine) ──────────────────────

    fn csb_promote(to: u16) -> crate::intel_gpu_rcs::CsbEntry {
        crate::intel_gpu_rcs::CsbEntry {
            lower: (to as u32) << 15,
            upper: (IDLE_SW_ID as u32) << 15,
        }
    }

    fn csb_complete(away: u16, to: u16) -> crate::intel_gpu_rcs::CsbEntry {
        crate::intel_gpu_rcs::CsbEntry {
            lower: (to as u32) << 15,
            upper: (away as u32) << 15,
        }
    }

    struct FakeHw {
        regs: FakeRegs,
        registry: FakeObjectRegistry,
        status_ggtt: u32,
        elsp_off: u64,
        write_ptr: u8,
        consumed_elsp: usize,
        /// A wedged engine: its ELSP bursts are never consumed
        /// and no CSB entries are ever posted.
        stuck: bool,
        /// Every batch start executed: (address, PPGTT ASI set).
        bb_log: Rc<RefCell<Vec<(u32, bool)>>>,
    }

    impl FakeHw {
        fn new(
            regs: FakeRegs,
            registry: FakeObjectRegistry,
            status_ggtt: u32,
            elsp_off: u64,
        ) -> Self {
            Self {
                regs,
                registry,
                status_ggtt,
                elsp_off,
                write_ptr: 0,
                consumed_elsp: 0,
                stuck: false,
                bb_log: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn bb_starts(&self) -> Vec<(u32, bool)> {
            self.bb_log.borrow().clone()
        }

        fn mem(&self, ggtt: u32) -> Rc<RefCell<Vec<u8>>> {
            self.registry
                .borrow()
                .get(&ggtt)
                .expect("fake hw: unknown GGTT object")
                .clone()
        }

        fn step(&mut self) {
            if self.stuck {
                return;
            }
            let elsp: Vec<u32> = self
                .regs
                .writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == self.elsp_off)
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

        fn execute(&mut self, desc: u64) {
            let image = self.mem(descriptor_lrca(desc));
            let rs = REG_STATE_PAGE_BYTE;
            let ring_start = mem_rd(
                &image,
                rs + ((crate::intel_gpu_rcs::CTX_RING_BUFFER_START + 1) as u64) * 4,
            );
            let head = mem_rd(
                &image,
                rs + ((crate::intel_gpu_rcs::CTX_RING_HEAD + 1) as u64) * 4,
            );
            let tail = mem_rd(
                &image,
                rs + ((crate::intel_gpu_rcs::CTX_RING_TAIL + 1) as u64) * 4,
            );
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
                        let addr = (lo | (hi << 32)) as u32;
                        self.bb_log
                            .borrow_mut()
                            .push((addr, dw & BB_START_ASI_PPGTT != 0));
                        self.execute_batch(addr);
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
            mem_wr(
                &image,
                rs + ((crate::intel_gpu_rcs::CTX_RING_HEAD + 1) as u64) * 4,
                tail,
            );
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

        fn push_csb(&mut self, entry: crate::intel_gpu_rcs::CsbEntry) {
            self.write_ptr = (self.write_ptr + 1) % CSB_ENTRIES;
            let status = self.mem(self.status_ggtt);
            let off = CSB_BUF_BYTE + (self.write_ptr as u64) * 8;
            mem_wr(&status, off, entry.lower);
            mem_wr(&status, off + 4, entry.upper);
            mem_wr(&status, CSB_WRITE_BYTE, self.write_ptr as u32);
        }
    }

    // ── Rig: one register file + one arena, many engines ────

    struct Rig {
        regs: FakeRegs,
        registry: FakeObjectRegistry,
        arena: SharedFakeArena,
    }

    impl Rig {
        fn new() -> Self {
            let registry: FakeObjectRegistry = Rc::new(RefCell::new(BTreeMap::new()));
            Self {
                regs: FakeRegs::new(),
                arena: SharedFakeArena(Rc::new(RefCell::new(FakeArena::new(registry.clone())))),
                registry,
            }
        }

        fn engine(
            &self,
            spec: EngineSpec,
        ) -> Result<(RcsEngine<FakeRegs, SharedFakeArena>, FakeHw), TestResult> {
            let eng = match RcsEngine::with_spec(spec, self.regs.clone(), self.arena.clone()) {
                Ok(e) => e,
                Err(_) => return Err(TestResult::Fail("engine init")),
            };
            let hw = FakeHw::new(
                self.regs.clone(),
                self.registry.clone(),
                eng.status_ggtt(),
                spec.elsp(),
            );
            Ok((eng, hw))
        }
    }

    // ── Table / codec fixtures ──────────────────────────────

    fn smoke_media_engine_table() -> TestResult {
        // The Gen12 set, pinned to the grounded values.
        if GEN12_MEDIA_ENGINES != [VCS0_SPEC, VCS1_SPEC, VECS0_SPEC] {
            return TestResult::Fail("Gen12 media engine set");
        }
        if VCS0_SPEC.base != 0x1C_0000
            || VCS1_SPEC.base != 0x1C_4000
            || VECS0_SPEC.base != 0x1C_8000
        {
            return TestResult::Fail("media ring bases");
        }
        if VCS0_SPEC.class != EngineClass::VideoDecode
            || VCS1_SPEC.class != EngineClass::VideoDecode
            || VECS0_SPEC.class != EngineClass::VideoEnhance
        {
            return TestResult::Fail("media engine classes");
        }
        if VCS0_SPEC.instance != 0 || VCS1_SPEC.instance != 1 || VECS0_SPEC.instance != 0 {
            return TestResult::Fail("media engine instances");
        }
        if GEN12_MEDIA_ENGINES.iter().any(|s| s.image_pages != 4) {
            return TestResult::Fail("media image bound");
        }
        if media_engines_for(RegionGeneration::Gen12).len() != 3 {
            return TestResult::Fail("inventory for Gen12");
        }
        // Xe-LPG media is a different (GuC-era) engine
        // generation this module does not drive: its inventory
        // is deliberately empty, never the Gen12 table.
        if !media_engines_for(RegionGeneration::XeLpg).is_empty() {
            return TestResult::Fail("inventory for XeLpg");
        }
        // Derived register addresses land in each engine's own
        // 0x4000 slot.
        if VCS0_SPEC.elsp() != 0x1C_0230
            || VCS1_SPEC.elsp() != 0x1C_4230
            || VECS0_SPEC.hws_pga() != 0x1C_8080
        {
            return TestResult::Fail("derived engine registers");
        }
        // Forcewake sub-domain mapping + register formulas.
        if MediaFwDomain::of(&VCS0_SPEC) != Some(MediaFwDomain::VdBox(0))
            || MediaFwDomain::of(&VCS1_SPEC) != Some(MediaFwDomain::VdBox(1))
            || MediaFwDomain::of(&VECS0_SPEC) != Some(MediaFwDomain::VeBox(0))
            || MediaFwDomain::of(&RCS0_SPEC).is_some()
        {
            return TestResult::Fail("forcewake domain mapping");
        }
        if MediaFwDomain::VdBox(1).set_reg() != 0xA544
            || MediaFwDomain::VdBox(1).ack_reg() != 0x0D54
            || MediaFwDomain::VeBox(0).set_reg() != 0xA560
            || MediaFwDomain::VeBox(0).ack_reg() != 0x0D70
        {
            return TestResult::Fail("forcewake register formulas");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_media", smoke_media_engine_table);

    fn smoke_media_descriptor_fields() -> TestResult {
        for spec in GEN12_MEDIA_ENGINES.iter() {
            let d = context_descriptor_for(spec, 0x1000_1000, 7);
            if descriptor_class(d) != spec.class.descriptor_value() {
                return TestResult::Fail("descriptor class field");
            }
            if descriptor_instance(d) != spec.instance {
                return TestResult::Fail("descriptor instance field");
            }
            if descriptor_sw_id(d) != 7 || descriptor_lrca(d) != 0x1000_1000 {
                return TestResult::Fail("descriptor id/lrca round-trip");
            }
        }
        // Class values are the Gen12-era descriptor numbering:
        // video decode 1, video enhance 2, render 0.
        if VCS0_SPEC.class.descriptor_value() != 1 || VECS0_SPEC.class.descriptor_value() != 2 {
            return TestResult::Fail("descriptor class numbering");
        }
        // The RCS descriptor is unchanged by the generalisation:
        // class 0, instance 0, identical to the spec form.
        let rcs = context_descriptor(0x1000_1000, 7);
        if rcs != context_descriptor_for(&RCS0_SPEC, 0x1000_1000, 7)
            || descriptor_class(rcs) != 0
            || descriptor_instance(rcs) != 0
        {
            return TestResult::Fail("RCS descriptor drifted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_media", smoke_media_descriptor_fields);

    fn smoke_media_reg_state_xcs() -> TestResult {
        let t = build_reg_state_for(&VECS0_SPEC, 0x1000_5000, RING_BYTES);
        if t[CTX_LRI_HEADER_0] != mi_load_register_imm(14, true) {
            return TestResult::Fail("XCS group 0 header");
        }
        // Register addresses are the engine's own.
        if t[CTX_CONTEXT_CONTROL] != 0x1C_8244 {
            return TestResult::Fail("XCS context control address");
        }
        if t[CTX_RING_BUFFER_START] != 0x1C_8038 || t[CTX_RING_BUFFER_START + 1] != 0x1000_5000 {
            return TestResult::Fail("XCS ring start pair");
        }
        if t[CTX_PDP3_UDW] != 0x1C_828C {
            return TestResult::Fail("XCS PDP3 UDW address");
        }
        // No render group: header 2 and the R_PWR_CLK_STATE
        // pair stay zero, terminator intact.
        if t[CTX_LRI_HEADER_2] != 0
            || t[CTX_R_PWR_CLK_STATE] != 0
            || t[CTX_R_PWR_CLK_STATE + 1] != 0
        {
            return TestResult::Fail("XCS template carries render group");
        }
        if t[CTX_END] != MI_BATCH_BUFFER_END | 1 {
            return TestResult::Fail("XCS template terminator");
        }
        // The RCS template is byte-identical through the
        // generalisation, render group included.
        if build_reg_state(0x1000_5000, RING_BYTES)
            != build_reg_state_for(&RCS0_SPEC, 0x1000_5000, RING_BYTES)
        {
            return TestResult::Fail("RCS template drifted");
        }
        let rcs = build_reg_state(0x1000_5000, RING_BYTES);
        if rcs[CTX_LRI_HEADER_2] != mi_load_register_imm(1, false) {
            return TestResult::Fail("RCS render group lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_media", smoke_media_reg_state_xcs);

    // ── Forcewake fixtures ──────────────────────────────────

    fn smoke_media_fw_conversation() -> TestResult {
        let regs = FakeRegs::new();
        let mut fw = MediaForcewake::new();
        let vd0 = MediaFwDomain::VdBox(0);
        // 0→1 programs the masked enable; the modelled ack
        // follows.
        if fw.acquire(&regs, vd0).is_err() {
            return TestResult::Fail("acquire vdbox0");
        }
        if fw.held(vd0) != 1 || regs.writes_to(0xA540) != [0x0001_0001] {
            return TestResult::Fail("enable write / hold count");
        }
        if regs.read32(0x0D50) & FORCEWAKE_KERNEL == 0 {
            return TestResult::Fail("ack did not follow request");
        }
        // Nested acquire: count only, no second write.
        if fw.acquire(&regs, vd0).is_err() || regs.writes_to(0xA540).len() != 1 {
            return TestResult::Fail("nested acquire programmed hardware");
        }
        // Releases: only the last one programs the clear.
        if fw.release(&regs, vd0).is_err() || regs.writes_to(0xA540).len() != 1 {
            return TestResult::Fail("inner release programmed hardware");
        }
        if fw.release(&regs, vd0).is_err() {
            return TestResult::Fail("outer release");
        }
        if regs.writes_to(0xA540) != [0x0001_0001, 0x0001_0000] || fw.held(vd0) != 0 {
            return TestResult::Fail("clear write / hold dropped");
        }
        if regs.read32(0x0D50) & FORCEWAKE_KERNEL != 0 {
            return TestResult::Fail("ack did not clear");
        }
        // Release without a hold is a typed refusal.
        if fw.release(&regs, vd0) != Err(MediaFwError::NotHeld { domain: vd0 }) {
            return TestResult::Fail("unheld release not refused");
        }
        // Sanitize clears every sub-domain and drops counts.
        if fw.acquire(&regs, MediaFwDomain::VeBox(0)).is_err() {
            return TestResult::Fail("acquire vebox0");
        }
        fw.sanitize(&regs);
        if fw.held(MediaFwDomain::VeBox(0)) != 0 {
            return TestResult::Fail("sanitize kept a hold");
        }
        for reg in [0xA540u64, 0xA544, 0xA560, 0xA564] {
            if !regs.writes_to(reg).contains(&0xFFFF_0000) {
                return TestResult::Fail("sanitize missed a sub-domain");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_media", smoke_media_fw_conversation);

    fn smoke_media_fw_ack_timeout_rolls_back() -> TestResult {
        let regs = FakeRegs::new();
        *regs.ack_enabled.borrow_mut() = false;
        let mut fw = MediaForcewake::new();
        let vd1 = MediaFwDomain::VdBox(1);
        match fw.acquire(&regs, vd1) {
            Err(MediaFwError::AckTimeout { domain }) if domain == vd1 => {}
            _ => return TestResult::Fail("acquire did not time out typed"),
        }
        // Request, re-kick clear, re-kick set, rollback clear —
        // and nothing is held afterwards.
        if regs.writes_to(0xA544) != [0x0001_0001, 0x0001_0000, 0x0001_0001, 0x0001_0000] {
            return TestResult::Fail("timeout write sequence");
        }
        if fw.held(vd1) != 0 {
            return TestResult::Fail("failed acquire held the domain");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media",
        smoke_media_fw_ack_timeout_rolls_back
    );

    // ── Submission fixtures ─────────────────────────────────

    fn smoke_media_submit_vcs0_write_for_write() -> TestResult {
        let rig = Rig::new();
        let (mut eng, mut hw) = match rig.engine(VCS0_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        // Bring-up programmed this engine's HWS_PGA and nothing
        // else's.
        if rig.regs.writes_to(0x1C_0080) != [eng.status_ggtt()]
            || !rig.regs.writes_to(0x2000 + 0x80).is_empty()
        {
            return TestResult::Fail("HWS_PGA conversation");
        }
        let ctx = match eng.create_context() {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("create context"),
        };
        let batch = match eng.write_batch(&[0, MI_BATCH_BUFFER_END]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("write batch"),
        };
        let batch_ggtt = batch.ggtt_offset();
        if eng.submit(ctx, batch).is_err() {
            return TestResult::Fail("submit");
        }
        // The doorbell burst at VCS0's ELSP, in hardware order
        // (port 1 zero pair first, then the port 0 descriptor),
        // and no other engine's ELSP was touched.
        let elsp = rig.regs.writes_to(0x1C_0230);
        if elsp.len() != 4 || elsp[0] != 0 || elsp[1] != 0 {
            return TestResult::Fail("ELSP burst shape");
        }
        let desc = ((elsp[2] as u64) << 32) | elsp[3] as u64;
        if descriptor_class(desc) != 1
            || descriptor_instance(desc) != 0
            || descriptor_sw_id(desc) != 1
        {
            return TestResult::Fail("ELSP descriptor fields");
        }
        // Arena order is deterministic: status, image, ring,
        // hwsp, batch.
        if eng.status_ggtt() != GGTT_ARENA_BASE || descriptor_lrca(desc) != GGTT_ARENA_BASE + 0x1000
        {
            return TestResult::Fail("context placement");
        }
        if !rig.regs.writes_to(0x1C_4230).is_empty() || !rig.regs.writes_to(0x1C_8230).is_empty() {
            return TestResult::Fail("another engine's ELSP was rung");
        }
        // The image in the shared registry carries VCS0's own
        // register addresses and the ring placement.
        let image = rig
            .registry
            .borrow()
            .get(&descriptor_lrca(desc))
            .expect("image in registry")
            .clone();
        let rs = REG_STATE_PAGE_BYTE;
        if mem_rd(&image, rs + (CTX_RING_BUFFER_START as u64) * 4) != 0x1C_0038
            || mem_rd(&image, rs + ((CTX_RING_BUFFER_START + 1) as u64) * 4)
                != GGTT_ARENA_BASE + 0x5000
        {
            return TestResult::Fail("image template addresses");
        }
        // Hardware runs it; the completion retires with the
        // breadcrumb in the context's own status page.
        hw.step();
        if hw.bb_starts() != [(batch_ggtt, false)] {
            return TestResult::Fail("batch start conversation");
        }
        let done = eng.poll_completions();
        if done.len() != 1 || done[0].ctx != ctx || done[0].seqno != 1 || done[0].request != 1 {
            return TestResult::Fail("completion");
        }
        if eng.hw_seqno(ctx) != Ok(1) {
            return TestResult::Fail("breadcrumb");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media",
        smoke_media_submit_vcs0_write_for_write
    );

    fn smoke_media_engines_do_not_alias() -> TestResult {
        // Masking-defeating: all three engines live at once
        // over one arena and one register file. If any pair of
        // engines aliased a ring, an image, a status page or a
        // doorbell, at least one assertion below breaks.
        let rig = Rig::new();
        let (mut vcs0, mut hw0) = match rig.engine(VCS0_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        let (mut vcs1, mut hw1) = match rig.engine(VCS1_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        let (mut vecs, mut hwv) = match rig.engine(VECS0_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        let statuses = [vcs0.status_ggtt(), vcs1.status_ggtt(), vecs.status_ggtt()];
        if statuses[0] == statuses[1] || statuses[1] == statuses[2] || statuses[0] == statuses[2] {
            return TestResult::Fail("status pages alias");
        }
        let mut ctxs = [None, None, None];
        for (i, eng) in [&mut vcs0, &mut vcs1, &mut vecs].into_iter().enumerate() {
            let ctx = match eng.create_context() {
                Ok(c) => c,
                Err(_) => return TestResult::Fail("create context"),
            };
            let batch = match eng.write_batch(&[0, MI_BATCH_BUFFER_END]) {
                Ok(b) => b,
                Err(_) => return TestResult::Fail("write batch"),
            };
            if eng.submit(ctx, batch).is_err() {
                return TestResult::Fail("submit");
            }
            ctxs[i] = Some(ctx);
        }
        // Each engine's doorbell carried its own descriptor:
        // classes/instances (1,0), (1,1), (2,0).
        let want = [(1u64, 0u8), (1, 1), (2, 0)];
        for (i, off) in [0x1C_0230u64, 0x1C_4230, 0x1C_8230].into_iter().enumerate() {
            let w = rig.regs.writes_to(off);
            if w.len() != 4 {
                return TestResult::Fail("doorbell burst per engine");
            }
            let desc = ((w[2] as u64) << 32) | w[3] as u64;
            if (descriptor_class(desc), descriptor_instance(desc)) != want[i] {
                return TestResult::Fail("descriptor identity per engine");
            }
        }
        hw0.step();
        hw1.step();
        hwv.step();
        // Each engine retires exactly its own context's
        // request; breadcrumbs land per engine.
        for (eng, ctx) in [
            (&mut vcs0, ctxs[0]),
            (&mut vcs1, ctxs[1]),
            (&mut vecs, ctxs[2]),
        ] {
            let ctx = ctx.expect("created");
            let done = eng.poll_completions();
            if done.len() != 1 || done[0].ctx != ctx || done[0].seqno != 1 {
                return TestResult::Fail("per-engine completion");
            }
            if eng.hw_seqno(ctx) != Ok(1) || eng.spurious_csb() != 0 {
                return TestResult::Fail("per-engine breadcrumb / CSB health");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media",
        smoke_media_engines_do_not_alias
    );

    fn smoke_media_wedged_engine_does_not_block_peers() -> TestResult {
        let rig = Rig::new();
        let (mut vcs0, mut hw0) = match rig.engine(VCS0_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        let (mut vecs, mut hwv) = match rig.engine(VECS0_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        hwv.stuck = true;
        // Queue work on both; VECS's hardware never answers.
        for eng in [&mut vcs0, &mut vecs] {
            let ctx = match eng.create_context() {
                Ok(c) => c,
                Err(_) => return TestResult::Fail("create context"),
            };
            let batch = match eng.write_batch(&[0, MI_BATCH_BUFFER_END]) {
                Ok(b) => b,
                Err(_) => return TestResult::Fail("write batch"),
            };
            if eng.submit(ctx, batch).is_err() {
                return TestResult::Fail("submit");
            }
        }
        hw0.step();
        hwv.step();
        if !vecs.poll_completions().is_empty() {
            return TestResult::Fail("wedged engine completed");
        }
        let done = vcs0.poll_completions();
        if done.len() != 1 {
            return TestResult::Fail("peer blocked by wedged engine");
        }
        // The healthy engine keeps accepting and retiring work.
        let ctx = done[0].ctx;
        let batch = match vcs0.write_batch(&[0, MI_BATCH_BUFFER_END]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("write batch 2"),
        };
        if vcs0.submit(ctx, batch).is_err() {
            return TestResult::Fail("second submit");
        }
        hw0.step();
        let done = vcs0.poll_completions();
        if done.len() != 1 || done[0].seqno != 2 {
            return TestResult::Fail("second completion");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media",
        smoke_media_wedged_engine_does_not_block_peers
    );

    fn smoke_media_ppgtt_va_batch() -> TestResult {
        let rig = Rig::new();
        let (mut eng, mut hw) = match rig.engine(VCS1_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        let ctx = match eng.create_context() {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("create context"),
        };
        // VA submission without an attached root is refused
        // and the batch is freed, not leaked.
        let live_before = eng.live_allocations();
        let batch = match eng.write_batch(&[0, MI_BATCH_BUFFER_END]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("write batch"),
        };
        if eng.submit_ppgtt(ctx, batch) != Err(SubmitError::PpgttNotAttached) {
            return TestResult::Fail("VA submit without root not refused");
        }
        if eng.live_allocations() != live_before {
            return TestResult::Fail("refused VA batch leaked");
        }
        // Attach a root; the PDP3 pair in the VCS1 image is the
        // patch site.
        if eng.attach_ppgtt(ctx, 0x4000_0000).is_err() {
            return TestResult::Fail("attach root");
        }
        let batch = match eng.write_batch(&[0, MI_BATCH_BUFFER_END]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("write batch 2"),
        };
        let batch_ggtt = batch.ggtt_offset();
        if eng.submit_ppgtt(ctx, batch).is_err() {
            return TestResult::Fail("VA submit");
        }
        hw.step();
        // The batch start the hardware executed carried the
        // PPGTT address-space indicator at the identity VA.
        if hw.bb_starts() != [(batch_ggtt, true)] {
            return TestResult::Fail("VA batch start form");
        }
        let done = eng.poll_completions();
        if done.len() != 1 || done[0].seqno != 1 {
            return TestResult::Fail("VA completion");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_media", smoke_media_ppgtt_va_batch);

    fn smoke_media_fw_wraps_submission() -> TestResult {
        // The production composition, fixture-shaped: the
        // sub-domain hold is taken before the submission's
        // doorbell and dropped after it.
        let rig = Rig::new();
        let (mut eng, mut hw) = match rig.engine(VCS0_SPEC) {
            Ok(p) => p,
            Err(f) => return f,
        };
        let mut fw = MediaForcewake::new();
        let ctx = match eng.create_context() {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("create context"),
        };
        let batch = match eng.write_batch(&[0, MI_BATCH_BUFFER_END]) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("write batch"),
        };
        if fw.acquire(&rig.regs, MediaFwDomain::VdBox(0)).is_err() {
            return TestResult::Fail("acquire");
        }
        if eng.submit(ctx, batch).is_err() {
            return TestResult::Fail("submit");
        }
        if fw.release(&rig.regs, MediaFwDomain::VdBox(0)).is_err() {
            return TestResult::Fail("release");
        }
        let enable_at = rig.regs.write_index(0xA540, 0x0001_0001);
        let elsp_at = rig
            .regs
            .writes
            .borrow()
            .iter()
            .position(|(o, _)| *o == 0x1C_0230);
        let clear_at = rig.regs.write_index(0xA540, 0x0001_0000);
        match (enable_at, elsp_at, clear_at) {
            (Some(e), Some(d), Some(c)) if e < d && d < c => {}
            _ => return TestResult::Fail("hold does not wrap the doorbell"),
        }
        hw.step();
        if eng.poll_completions().len() != 1 {
            return TestResult::Fail("completion under hold composition");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_media",
        smoke_media_fw_wraps_submission
    );
}
