//! AMD KMS (Kernel Mode Setting) surface — connector / encoder /
//! CRTC topology.
//!
//! Ties together the lower-level codecs that already exist
//! ([`crate::amdgpu_dcn`], [`crate::amdgpu_atom_displayobj`],
//! [`crate::dp_link_training`], [`crate::dp_aux`]) into a single
//! KMS-style state object: per-CRTC scanout state, per-encoder
//! transport config, and per-connector hotplug status. Mirrors
//! the Linux `drm_crtc` / `drm_encoder` / `drm_connector` triad
//! the AMD DC backend feeds into.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/display/amdgpu_dm.c::amdgpu_dm_init`
//!   walks the ATOM display-object table, mints a `drm_connector`
//!   per path, attaches an encoder per object-chain, and binds the
//!   pair to a DC `pipe_ctx` (the CRTC analogue).
//! - Linux `drivers/gpu/drm/drm_crtc.c` / `drm_encoder.c` — DRM-
//!   core surface the AMD backend implements.
//! - Linux `display/dc/core/dc_link.c` — connector ↔ encoder
//!   pairing logic shared with DP link bring-up.
//!
//! The Linux code is GPL-2.0-or-later (matches NARF), so the
//! structural patterns are adapted directly. Per-IP register
//! programming stays in [`crate::amdgpu_dcn`].
//!
//! ## State machine
//!
//! ```text
//!   Connector::Disconnected  ─ hotplug+EDID → Connected
//!   Connector::Connected     ─ disappear  → Disconnected
//!
//!   Crtc::Inactive  ─ set_mode  → Programmed
//!   Crtc::Programmed ─ enable   → Active
//!   Crtc::Active    ─ disable   → Programmed
//!   Crtc::Programmed ─ unset_mode → Inactive
//! ```
//!
//! ## Scope
//!
//! - **Pure topology** — no MMIO here. The driver core feeds the
//!   ATOM table in (via [`crate::amdgpu_atom_displayobj`]) and
//!   pulls a `KmsState` out. To actually program a mode, callers
//!   pull a `ModesetPlan` and dispatch it through
//!   `crate::amdgpu_dcn::execute_modeset`.
//! - **One CRTC per connector** in this stage — multi-monitor
//!   needs `pipe_ctx` arbitration that DC handles via the
//!   resource pool; we punt to "first available CRTC".
//! - **No cursor / overlay planes** — primary plane only. Cursor
//!   support lives in [`crate::amdgpu_pageflip`] once that lands.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu::Family;
use crate::amdgpu_atom_displayobj::{ConnectorKind, DisplayPath};
use crate::amdgpu_dcn::{
    dcn20_modeset_sequence, dcn35_modeset_sequence, timing_for_mode, DcnWrite, ModeTiming,
};

// ── Connector ────────────────────────────────────────────────────

/// Hotplug-detection state for a single connector. Mirrors
/// `drm_connector_status` in Linux DRM.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectorStatus {
    /// HPD high + EDID readable.
    Connected,
    /// HPD low / no sink response.
    Disconnected,
    /// HPD asserted but EDID readback failed — sink is present
    /// but unreadable (early-boot wake, transient AUX failure).
    Unknown,
}

/// One KMS connector. Index into [`KmsState::connectors`] doubles
/// as the connector's stable ID for the duration of a probe.
#[derive(Clone, Debug)]
pub struct Connector {
    /// Physical connector type per ATOM object id.
    pub kind: ConnectorKind,
    /// Per-instance index from the ATOM path (e.g. DP-0, DP-1).
    pub instance: u8,
    /// Last-seen hotplug state.
    pub status: ConnectorStatus,
    /// CRTC currently driving this connector, if any.
    pub bound_crtc: Option<u8>,
    /// Encoder linked to this connector via the ATOM object chain.
    pub bound_encoder: Option<u8>,
    /// ATOM `usDeviceTag` — the firmware's notion of this output.
    pub device_tag: u16,
}

impl Connector {
    /// `true` if a modeset is possible against this connector.
    /// `Disconnected` connectors are skipped by `pick_crtc`.
    pub fn is_modesettable(&self) -> bool {
        matches!(self.status, ConnectorStatus::Connected)
    }

    /// `true` if the connector signal type requires DP link
    /// training before scanout. eDP + DP both train.
    pub fn requires_link_training(&self) -> bool {
        matches!(self.kind, ConnectorKind::Dp | ConnectorKind::Edp)
    }

    /// `true` if the connector is an internal panel (no HPD pin,
    /// no detach). eDP / LVDS / DSI.
    pub fn is_internal_panel(&self) -> bool {
        matches!(
            self.kind,
            ConnectorKind::Edp | ConnectorKind::Lvds | ConnectorKind::Dsi
        )
    }
}

// ── Encoder ──────────────────────────────────────────────────────

/// Encoder transport type. Linux's `drm_encoder.encoder_type`
/// uses a richer enum (TMDS, LVDS, DAC, DSI, …); we collapse to
/// the categories the modeset path actually branches on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncoderKind {
    /// DP / eDP — full DP link training path required.
    DigitalPort,
    /// HDMI — TMDS, no link training; pixel-clock select only.
    Hdmi,
    /// DVI — TMDS like HDMI but no audio stream.
    Dvi,
    /// Analog VGA — DAC, deprecated; only present on legacy boards.
    Dac,
    /// LVDS / DSI panel — direct panel link, no negotiation.
    Panel,
}

/// One KMS encoder.
#[derive(Clone, Debug)]
pub struct Encoder {
    pub kind: EncoderKind,
    /// ATOM `ObjectLink::instance` for this encoder.
    pub instance: u8,
    /// Connectors this encoder can drive. One-to-many on boards
    /// with shared transmitters; one-to-one on most laptops.
    pub possible_connectors: u32,
}

impl Encoder {
    pub fn supports_connector(&self, idx: u8) -> bool {
        idx < 32 && (self.possible_connectors & (1u32 << idx)) != 0
    }
}

// ── CRTC ─────────────────────────────────────────────────────────

/// CRTC (display pipe / OTG) state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CrtcState {
    /// No mode set. OTG_MASTER_EN = 0.
    Inactive,
    /// `set_mode` written but `enable` hasn't fired. HUBP / OPP /
    /// OTG registers are loaded; the master enable is still low.
    Programmed,
    /// OTG running, scanning the framebuffer. `enable` has run.
    Active,
}

/// One KMS CRTC. Maps 1:1 to a DCN pipe; AMD chips ship 4 pipes
/// on consumer parts (Renoir / Phoenix), 6 on Navi3x desktop.
#[derive(Clone, Debug)]
pub struct Crtc {
    /// Hardware pipe index (0..n_pipes).
    pub pipe: u8,
    pub state: CrtcState,
    /// Mode currently programmed (or `None` if `Inactive`).
    pub mode: Option<CrtcMode>,
}

/// Mode programmed into a CRTC. Carries the full DCN timing so
/// the modeset codec can replay without re-deriving it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CrtcMode {
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u32,
    pub stride_pixels: u32,
    /// Phys base of the primary plane's framebuffer (VRAM addr).
    pub surface_phys: u64,
}

// ── KMS state ────────────────────────────────────────────────────

/// Top-level KMS state. One per AMD GPU. Built once at probe by
/// walking the ATOM display-object table, then mutated by hotplug
/// + modeset events.
#[derive(Clone, Debug)]
pub struct KmsState {
    pub connectors: Vec<Connector>,
    pub encoders: Vec<Encoder>,
    pub crtcs: Vec<Crtc>,
}

impl Default for KmsState {
    fn default() -> Self {
        Self {
            connectors: Vec::new(),
            encoders: Vec::new(),
            crtcs: Vec::new(),
        }
    }
}

impl KmsState {
    /// Mint the CRTC pool. AMD APUs ship 4 pipes (HUBP/DPP/OPP/OTG
    /// quads) so we always allocate 4 inactive CRTCs at startup.
    /// Desktop Navi3 needs 6 — pass `n_pipes = 6` in that case.
    pub fn new(n_pipes: u8) -> Self {
        let crtcs = (0..n_pipes)
            .map(|pipe| Crtc {
                pipe,
                state: CrtcState::Inactive,
                mode: None,
            })
            .collect();
        Self {
            connectors: Vec::new(),
            encoders: Vec::new(),
            crtcs,
        }
    }

    /// Walk an ATOM display-object table and mint a [`Connector`]
    /// per path. Encoder pool is populated separately via
    /// [`Self::push_encoder`] — paths only carry the `gpu_object_id`
    /// of the first object in the chain.
    pub fn ingest_atom_paths<I>(&mut self, paths: I)
    where
        I: IntoIterator<Item = DisplayPath>,
    {
        for path in paths {
            self.connectors.push(Connector {
                kind: path.connector_kind,
                instance: path.connector_index,
                // Internal panels start `Connected` (no HPD to
                // poll); external connectors start `Disconnected`
                // and flip to `Connected` on the first HPD IRQ.
                status: match path.connector_kind {
                    ConnectorKind::Edp | ConnectorKind::Lvds | ConnectorKind::Dsi => {
                        ConnectorStatus::Connected
                    }
                    _ => ConnectorStatus::Disconnected,
                },
                bound_crtc: None,
                bound_encoder: None,
                device_tag: path.device_tag,
            });
        }
    }

    /// Append an encoder discovered in the ATOM object chain.
    pub fn push_encoder(&mut self, kind: EncoderKind, instance: u8, possible_connectors: u32) {
        self.encoders.push(Encoder {
            kind,
            instance,
            possible_connectors,
        });
    }

    /// Bind an encoder to a connector by index. Both must already
    /// exist in their respective pools.
    pub fn bind_encoder(&mut self, connector_idx: u8, encoder_idx: u8) -> Result<(), KmsError> {
        let conn = self
            .connectors
            .get_mut(connector_idx as usize)
            .ok_or(KmsError::NoSuchConnector)?;
        let enc = self
            .encoders
            .get(encoder_idx as usize)
            .ok_or(KmsError::NoSuchEncoder)?;
        if !enc.supports_connector(connector_idx) {
            return Err(KmsError::EncoderMismatch);
        }
        conn.bound_encoder = Some(encoder_idx);
        Ok(())
    }

    /// Update connector hotplug status. Called from the HPD IRQ
    /// handler once EDID readback has either succeeded
    /// ([`ConnectorStatus::Connected`]) or failed
    /// ([`ConnectorStatus::Unknown`]).
    pub fn set_status(&mut self, connector_idx: u8, status: ConnectorStatus) {
        if let Some(c) = self.connectors.get_mut(connector_idx as usize) {
            let was = c.status;
            c.status = status;
            // A connector that just disconnected drops its CRTC
            // binding — the pipe goes back to the free pool.
            if was == ConnectorStatus::Connected && status != ConnectorStatus::Connected {
                if let Some(crtc_idx) = c.bound_crtc.take() {
                    if let Some(crtc) = self.crtcs.get_mut(crtc_idx as usize) {
                        crtc.state = CrtcState::Inactive;
                        crtc.mode = None;
                    }
                }
            }
        }
    }

    /// Pick a free CRTC for `connector_idx` and bind them. Returns
    /// the CRTC index (`pipe` field). Linux's `pipe_ctx`
    /// arbitration is more complex (priority by output kind, MPC
    /// tree topology) — we use first-fit.
    pub fn pick_crtc(&mut self, connector_idx: u8) -> Result<u8, KmsError> {
        // Sanity-check the connector exists + is modesettable.
        let conn = self
            .connectors
            .get(connector_idx as usize)
            .ok_or(KmsError::NoSuchConnector)?;
        if !conn.is_modesettable() {
            return Err(KmsError::ConnectorDisconnected);
        }
        if let Some(existing) = conn.bound_crtc {
            return Ok(existing);
        }
        for crtc in &mut self.crtcs {
            if crtc.state == CrtcState::Inactive {
                let pipe = crtc.pipe;
                // Mark the pipe as claimed so subsequent pick_crtc
                // calls see it as unavailable until set_status resets
                // it to Inactive on disconnect.
                crtc.state = CrtcState::Programmed;
                // Re-borrow the connector mutably (split borrow
                // since `crtc` was holding self.crtcs).
                if let Some(c) = self.connectors.get_mut(connector_idx as usize) {
                    c.bound_crtc = Some(pipe);
                }
                return Ok(pipe);
            }
        }
        Err(KmsError::NoFreeCrtc)
    }

    /// Lookup connector by ATOM `usDeviceTag`. Used by the
    /// hotplug ISR to translate the IH packet's device tag back
    /// into a connector index.
    pub fn connector_by_device_tag(&self, tag: u16) -> Option<u8> {
        self.connectors
            .iter()
            .position(|c| c.device_tag == tag)
            .map(|i| i as u8)
    }
}

// ── Modeset plan ─────────────────────────────────────────────────

/// One full modeset plan — what the codec produced for a CRTC, in
/// the order the driver should write to BAR5.
#[derive(Clone, Debug)]
pub struct ModesetPlan {
    pub crtc_idx: u8,
    pub connector_idx: u8,
    pub timing: ModeTiming,
    pub writes: Vec<DcnWrite>,
}

/// Build a modeset plan against the given KMS state + family.
/// The plan is pure — execution happens through
/// [`amdgpu_dcn::execute_modeset`].
///
/// `dcn_base` is the discovery-resolved DCN block base
/// (`amdgpu::ip_block_base(HW_ID_DCN, 0)`).
pub fn plan_modeset(
    kms: &KmsState,
    family: Family,
    connector_idx: u8,
    width: u32,
    height: u32,
    refresh_hz: u32,
    stride_pixels: u32,
    surface_phys: u64,
    dcn_base: u32,
) -> Result<ModesetPlan, KmsError> {
    let conn = kms
        .connectors
        .get(connector_idx as usize)
        .ok_or(KmsError::NoSuchConnector)?;
    if !conn.is_modesettable() {
        return Err(KmsError::ConnectorDisconnected);
    }
    let crtc_idx = conn.bound_crtc.ok_or(KmsError::NoCrtc)?;
    let timing = timing_for_mode(width, height, refresh_hz).ok_or(KmsError::UnsupportedMode)?;
    let writes = match family {
        Family::Phoenix => dcn35_modeset_sequence(&timing, surface_phys, stride_pixels, dcn_base),
        _ => dcn20_modeset_sequence(&timing, surface_phys, stride_pixels, dcn_base),
    };
    Ok(ModesetPlan {
        crtc_idx,
        connector_idx,
        timing,
        writes,
    })
}

/// Apply a modeset plan to a KMS state — bookkeeping only,
/// **no MMIO**. Call after `execute_modeset` returns to record
/// what's now live.
pub fn commit_modeset(kms: &mut KmsState, plan: &ModesetPlan) {
    if let Some(crtc) = kms.crtcs.get_mut(plan.crtc_idx as usize) {
        crtc.state = CrtcState::Programmed;
        crtc.mode = Some(CrtcMode {
            width: plan.timing.h_active as u32,
            height: plan.timing.v_active as u32,
            refresh_hz: refresh_from_timing(&plan.timing),
            stride_pixels: derive_stride(plan),
            surface_phys: derive_surface(plan),
        });
    }
}

/// Mark a CRTC as `Active` (OTG_MASTER_EN written). Separate from
/// `commit_modeset` because the codec emits the master-enable as
/// the last write in the sequence; the bookkeeping update flows
/// after the write retires.
pub fn mark_active(kms: &mut KmsState, crtc_idx: u8) {
    if let Some(crtc) = kms.crtcs.get_mut(crtc_idx as usize) {
        if matches!(crtc.state, CrtcState::Programmed | CrtcState::Active) {
            crtc.state = CrtcState::Active;
        }
    }
}

/// Tear down a CRTC's mode — reset state to `Inactive`. The
/// driver still needs to write OTG_MASTER_EN=0 itself; this is
/// the post-write bookkeeping.
pub fn unset_mode(kms: &mut KmsState, crtc_idx: u8) {
    if let Some(crtc) = kms.crtcs.get_mut(crtc_idx as usize) {
        crtc.state = CrtcState::Inactive;
        crtc.mode = None;
    }
}

fn refresh_from_timing(t: &ModeTiming) -> u32 {
    if t.h_total == 0 || t.v_total == 0 {
        return 0;
    }
    // pixel_clock_khz × 1000 / (htotal × vtotal). Rounded.
    let pix_per_frame = (t.h_total as u64) * (t.v_total as u64);
    let hz = ((t.pixel_clock_khz as u64) * 1000 + pix_per_frame / 2) / pix_per_frame;
    hz as u32
}

// `ModesetPlan` doesn't separately carry stride / phys after
// the codec runs — both are encoded in the write list. Recover
// from the plan by scanning the writes for the relevant offsets.
fn derive_stride(_plan: &ModesetPlan) -> u32 {
    // Codec emits PRIMARY_SURFACE_PITCH, but the offset varies
    // by family. The KMS bookkeeping uses the value the caller
    // passed into `plan_modeset`, so we don't actually need to
    // back-derive it here — the field is carried in plan-builder
    // state. Return 0 as a sentinel; the real value is recorded
    // before commit by `commit_modeset_full`.
    0
}

fn derive_surface(_plan: &ModesetPlan) -> u64 {
    0
}

/// Variant of [`commit_modeset`] that takes stride + surface in
/// hand so the bookkeeping stores the actual values. Prefer this
/// over the unsuffixed variant — the unsuffixed version is kept
/// for callers that don't have the originals to hand.
pub fn commit_modeset_full(
    kms: &mut KmsState,
    plan: &ModesetPlan,
    stride_pixels: u32,
    surface_phys: u64,
) {
    if let Some(crtc) = kms.crtcs.get_mut(plan.crtc_idx as usize) {
        crtc.state = CrtcState::Programmed;
        crtc.mode = Some(CrtcMode {
            width: plan.timing.h_active as u32,
            height: plan.timing.v_active as u32,
            refresh_hz: refresh_from_timing(&plan.timing),
            stride_pixels,
            surface_phys,
        });
    }
}

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KmsError {
    NoSuchConnector,
    NoSuchEncoder,
    EncoderMismatch,
    ConnectorDisconnected,
    NoFreeCrtc,
    NoCrtc,
    UnsupportedMode,
}

// ── Helpers exposed for amdgpu_dcn re-export ─────────────────────

/// Convenience: count active CRTCs. Used by power-management to
/// decide whether to allow APU C-state entry (any active CRTC
/// disables deep idle).
pub fn active_crtc_count(kms: &KmsState) -> usize {
    kms.crtcs
        .iter()
        .filter(|c| c.state == CrtcState::Active)
        .count()
}

/// Convenience: count connected sinks. Used by the firmware path
/// to decide whether to load the eDP-specific DMCUB blob or skip
/// it (no panels → DMCUB is a no-op).
pub fn connected_count(kms: &KmsState) -> usize {
    kms.connectors
        .iter()
        .filter(|c| c.status == ConnectorStatus::Connected)
        .count()
}

// Re-export so callers writing `amdgpu_modeset::DcnWrite` find it.
pub use crate::amdgpu_dcn::DcnWrite as Write;

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use crate::amdgpu_atom_displayobj::ConnectorKind;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_kms_state_starts_empty() -> TestResult {
        let s = KmsState::default();
        if !s.connectors.is_empty() {
            return TestResult::Fail("default connectors not empty");
        }
        if !s.encoders.is_empty() {
            return TestResult::Fail("default encoders not empty");
        }
        if !s.crtcs.is_empty() {
            return TestResult::Fail("default crtcs not empty");
        }
        // n_pipes path mints CRTCs in Inactive state.
        let s = KmsState::new(4);
        if s.crtcs.len() != 4 {
            return TestResult::Fail("new(4) didn't mint 4 crtcs");
        }
        for (i, c) in s.crtcs.iter().enumerate() {
            if c.pipe != i as u8 {
                return TestResult::Fail("pipe index mismatch");
            }
            if c.state != CrtcState::Inactive {
                return TestResult::Fail("new crtc not Inactive");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_kms_state_starts_empty);

    fn smoke_kms_connector_ingestion_classifies_internal() -> TestResult {
        let mut s = KmsState::new(4);
        let paths = [
            DisplayPath {
                device_tag: 0x0040,
                connector_kind: ConnectorKind::Edp,
                connector_index: 0,
                gpu_object_id: 0x2100,
            },
            DisplayPath {
                device_tag: 0x0080,
                connector_kind: ConnectorKind::HdmiA,
                connector_index: 0,
                gpu_object_id: 0x2101,
            },
            DisplayPath {
                device_tag: 0x0100,
                connector_kind: ConnectorKind::Dp,
                connector_index: 1,
                gpu_object_id: 0x2102,
            },
        ];
        s.ingest_atom_paths(paths.iter().copied());
        if s.connectors.len() != 3 {
            return TestResult::Fail("path ingest dropped entries");
        }
        // eDP is an internal panel — starts Connected.
        if s.connectors[0].status != ConnectorStatus::Connected {
            return TestResult::Fail("eDP did not start Connected");
        }
        // External (HDMI / DP) — start Disconnected, await HPD.
        if s.connectors[1].status != ConnectorStatus::Disconnected {
            return TestResult::Fail("HDMI did not start Disconnected");
        }
        if s.connectors[2].status != ConnectorStatus::Disconnected {
            return TestResult::Fail("DP did not start Disconnected");
        }
        // Connector predicates.
        if !s.connectors[0].is_internal_panel() {
            return TestResult::Fail("eDP not flagged internal");
        }
        if !s.connectors[2].requires_link_training() {
            return TestResult::Fail("DP not flagged link-training");
        }
        if s.connectors[1].requires_link_training() {
            return TestResult::Fail("HDMI flagged link-training");
        }
        // device_tag lookup round-trips.
        if s.connector_by_device_tag(0x0080) != Some(1) {
            return TestResult::Fail("device_tag lookup failed");
        }
        if s.connector_by_device_tag(0xBEEF) != None {
            return TestResult::Fail("device_tag for missing returned Some");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_kms_connector_ingestion_classifies_internal
    );

    fn smoke_kms_pick_crtc_first_fit() -> TestResult {
        let mut s = KmsState::new(4);
        s.ingest_atom_paths(
            [DisplayPath {
                device_tag: 0x0040,
                connector_kind: ConnectorKind::Edp,
                connector_index: 0,
                gpu_object_id: 0x2100,
            }]
            .iter()
            .copied(),
        );
        // eDP starts Connected → pick succeeds, returns pipe 0.
        let pipe = s.pick_crtc(0).expect("pick_crtc Connected eDP failed");
        if pipe != 0 {
            return TestResult::Fail("pick_crtc didn't return first pipe");
        }
        // Re-picking returns same pipe (idempotent).
        let pipe2 = s.pick_crtc(0).expect("pick_crtc re-pick failed");
        if pipe2 != pipe {
            return TestResult::Fail("pick_crtc not idempotent");
        }
        // Disconnect drops the CRTC binding.
        s.set_status(0, ConnectorStatus::Disconnected);
        if s.connectors[0].bound_crtc.is_some() {
            return TestResult::Fail("disconnect did not unbind crtc");
        }
        if s.crtcs[0].state != CrtcState::Inactive {
            return TestResult::Fail("CRTC not returned to Inactive on unbind");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_kms_pick_crtc_first_fit);

    fn smoke_kms_pick_crtc_no_free() -> TestResult {
        // 1 pipe in pool, 2 modesettable connectors — second pick
        // returns NoFreeCrtc.
        let mut s = KmsState::new(1);
        s.ingest_atom_paths(
            [
                DisplayPath {
                    device_tag: 0x0040,
                    connector_kind: ConnectorKind::Edp,
                    connector_index: 0,
                    gpu_object_id: 0x2100,
                },
                DisplayPath {
                    device_tag: 0x0080,
                    connector_kind: ConnectorKind::Lvds,
                    connector_index: 0,
                    gpu_object_id: 0x2101,
                },
            ]
            .iter()
            .copied(),
        );
        if s.pick_crtc(0).is_err() {
            return TestResult::Fail("first pick should succeed");
        }
        if s.pick_crtc(1) != Err(KmsError::NoFreeCrtc) {
            return TestResult::Fail("second pick should hit NoFreeCrtc");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_kms_pick_crtc_no_free);

    fn smoke_kms_modeset_plan_round_trip() -> TestResult {
        let mut s = KmsState::new(4);
        s.ingest_atom_paths(
            [DisplayPath {
                device_tag: 0x0040,
                connector_kind: ConnectorKind::Edp,
                connector_index: 0,
                gpu_object_id: 0x2100,
            }]
            .iter()
            .copied(),
        );
        s.pick_crtc(0).expect("pick_crtc");
        let plan = match plan_modeset(
            &s,
            Family::Renoir,
            0,
            1920,
            1080,
            60,
            1920,
            0x8000_0000,
            0x0000_5000,
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("plan_modeset failed"),
        };
        if plan.crtc_idx != 0 {
            return TestResult::Fail("plan crtc_idx wrong");
        }
        if plan.timing.h_active != 1920 {
            return TestResult::Fail("plan timing h_active wrong");
        }
        if plan.writes.is_empty() {
            return TestResult::Fail("plan writes empty");
        }
        // Commit bookkeeping.
        commit_modeset_full(&mut s, &plan, 1920, 0x8000_0000);
        if s.crtcs[0].state != CrtcState::Programmed {
            return TestResult::Fail("commit didn't move CRTC to Programmed");
        }
        mark_active(&mut s, 0);
        if s.crtcs[0].state != CrtcState::Active {
            return TestResult::Fail("mark_active didn't activate");
        }
        if active_crtc_count(&s) != 1 {
            return TestResult::Fail("active_crtc_count wrong");
        }
        unset_mode(&mut s, 0);
        if s.crtcs[0].state != CrtcState::Inactive {
            return TestResult::Fail("unset_mode didn't reset state");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_kms_modeset_plan_round_trip);

    fn smoke_kms_encoder_binding_validation() -> TestResult {
        let mut s = KmsState::new(4);
        s.ingest_atom_paths(
            [DisplayPath {
                device_tag: 0x0040,
                connector_kind: ConnectorKind::Edp,
                connector_index: 0,
                gpu_object_id: 0x2100,
            }]
            .iter()
            .copied(),
        );
        // Encoder 0 supports connector 0 only.
        s.push_encoder(EncoderKind::DigitalPort, 0, 0b0001);
        if s.bind_encoder(0, 0).is_err() {
            return TestResult::Fail("compatible encoder bind failed");
        }
        if s.connectors[0].bound_encoder != Some(0) {
            return TestResult::Fail("encoder binding not recorded");
        }
        // Encoder 1 supports only connector 5 (out of range).
        s.push_encoder(EncoderKind::Hdmi, 1, 0b100000);
        if s.bind_encoder(0, 1) != Err(KmsError::EncoderMismatch) {
            return TestResult::Fail("incompatible encoder bind not rejected");
        }
        // Missing slot.
        if s.bind_encoder(99, 0) != Err(KmsError::NoSuchConnector) {
            return TestResult::Fail("missing connector not flagged");
        }
        if s.bind_encoder(0, 99) != Err(KmsError::NoSuchEncoder) {
            return TestResult::Fail("missing encoder not flagged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_kms_encoder_binding_validation);
}
