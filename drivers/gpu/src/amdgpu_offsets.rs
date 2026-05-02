//! Per-family register-offset registration — clean-room.
//!
//! The bring-up paths in `amdgpu` need a handful of per-family
//! register-bus offsets:
//!
//! - **MP0 base** for the PSP firmware-load mailbox.
//! - **DCN HUBP/OPP/OTG block bases** for the modeset register
//!   sequence.
//! - **DCN-AUX block base** for the EDID / link-training transport.
//! - **GFX ring-buffer base register** for ring submission.
//!
//! Stage-1..Stage-6 left these as compile-time constants per
//! family — Vega + Navi1 sourced from public AMD GPUOpen IP
//! tables, others marked `None` so bring-up fails closed.
//!
//! Stage-7 promotes the table to a runtime registry: a build
//! profile or boot-time payload can call
//! `register_family_offsets(family, offsets)` to plug in values
//! without touching the driver core. Two consumers in particular:
//!
//! 1. The trusted-bootstrap path on a board with the AMD PPR
//!    (Processor Programmer's Reference) sourced — register the
//!    family's offsets at boot, then `Family::offsets()` returns
//!    them for `load_firmware` / `set_mode`.
//! 2. A future debugfs-shaped surface that lets userspace plug
//!    offsets in at runtime (a one-shot, debug-build-only path).
//!
//! Why a runtime table instead of a compile-time one: the AMD PPR
//! is large, family-specific, and the offsets are facts about
//! silicon (not creative work) but **transcribing the PPR's
//! tables into our source tree is a derivative work in scope of
//! AMD's documentation copyright**. A runtime registry separates
//! the question "where do these numbers come from" (boot path's
//! problem) from "how does the driver consume them" (this
//! crate's problem); a future maintainer with the PPR in hand
//! fills in the registration site.
//!
//! ## Mapping reference
//!
//! Each offset's spec home is documented inline so a future
//! maintainer can find the canonical value without re-deriving
//! it. References are AMD PPR section numbers; the PPR is
//! published per-SoC by AMD on developer.amd.com.

use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu::Family;

/// Register-bus offsets for a single AMD GPU family. All values
/// are in the BAR5 register-window byte address space.
#[derive(Copy, Clone, Debug, Default)]
pub struct FamilyOffsets {
    /// MP0 (PSP) register block base. Used by the PSP firmware-
    /// load handshake (`MP0_C2PMSG_64/_67/_69` are at
    /// `mp0_base + 0x29C + N*4`).
    /// Source: AMD PPR §"Microcontroller Firmware Loading", per
    /// SoC.
    pub mp0_base:        Option<u32>,
    /// DCN HUBP (Hub Pixel Pipe) block base — primary surface
    /// address / pitch / blanking control registers.
    /// Source: AMD PPR §"Display Core Next" register tables.
    pub dcn_hubp_base:   Option<u32>,
    /// DCN OPP (Output Pixel Processor) block base — gamma
    /// passthrough, output-format control.
    pub dcn_opp_base:    Option<u32>,
    /// DCN OTG (Output Timing Generator) block base — H_TOTAL /
    /// V_TOTAL / sync-pulse timing registers.
    pub dcn_otg_base:    Option<u32>,
    /// DCN AUX block base — implements DP AUX transactions
    /// against the connected sink.
    pub dcn_aux_base:    Option<u32>,
    /// GFX (graphics core) ring-buffer base register. Programmed
    /// with the phys address of `Ring::phys_addr()` at engine
    /// bring-up.
    pub gfx_rb_base:     Option<u32>,
}

impl FamilyOffsets {
    pub const fn empty() -> Self {
        Self {
            mp0_base: None,
            dcn_hubp_base: None,
            dcn_opp_base: None,
            dcn_otg_base: None,
            dcn_aux_base: None,
            gfx_rb_base: None,
        }
    }
}

/// One slot per `Family` variant. Indexed by `family as usize`.
/// Default-empty so callers without registered offsets fall
/// back to the compile-time MP0 base in
/// `Family::mp0_base()`.
const N_FAMILIES: usize = 5; // Vega / Renoir / Navi1 / Navi2 / Navi3

static REGISTRY: IrqSafeSpinLock<[FamilyOffsets; N_FAMILIES]>
    = IrqSafeSpinLock::new([FamilyOffsets::empty(); N_FAMILIES]);

fn family_index(f: Family) -> usize {
    match f {
        Family::Vega   => 0,
        Family::Renoir => 1,
        Family::Navi1  => 2,
        Family::Navi2  => 3,
        Family::Navi3  => 4,
    }
}

/// Plug a family's offsets into the runtime registry. Idempotent
/// on `family`. The trusted bootstrap calls this once per family
/// the kernel image expects to encounter.
pub fn register_family_offsets(family: Family, offsets: FamilyOffsets) {
    let idx = family_index(family);
    REGISTRY.lock()[idx] = offsets;
}

/// Borrow `family`'s registered offsets. Returns
/// `FamilyOffsets::empty()` when no registration has happened —
/// callers must check each individual `Option` before trusting
/// the value.
pub fn offsets_of(family: Family) -> FamilyOffsets {
    REGISTRY.lock()[family_index(family)]
}

/// Number of families with at least one offset registered.
/// Diagnostic / observability surface.
pub fn registered_count() -> usize {
    let g = REGISTRY.lock();
    g.iter()
        .filter(|o|
            o.mp0_base.is_some() || o.dcn_hubp_base.is_some()
            || o.dcn_opp_base.is_some() || o.dcn_otg_base.is_some()
            || o.dcn_aux_base.is_some() || o.gfx_rb_base.is_some()
        )
        .count()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = REGISTRY.lock();
    *g = [FamilyOffsets::empty(); N_FAMILIES];
}
