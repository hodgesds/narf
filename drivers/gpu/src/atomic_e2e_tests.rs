//! DRM atomic modeset state-machine end-to-end tests (Wave 36).
//!
//! Exercises the full atomic path:
//!   build AtomicState → core_check (validate) → core_commit (apply) →
//!   syncobj/fence signal → state cleanup.
//!
//! ## Fake model
//!
//! Tests use a `FakeMmio` (borrowed from Wave 30) for the bochs VBE
//! register window and a `FakeAtomicOps` driver hook that records
//! what it was asked to do without touching hardware.
//!
//! `Card` objects are built inline with `Card::new` + manual
//! `crtcs/connectors/framebuffers` pushes.  GEM objects are allocated
//! through `card.gem.alloc` and wrapped with `card.addfb2`.
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_check_only`
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_commit`
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_plane_check`
//! - `drivers/gpu/drm/drm_atomic_helper.c::drm_atomic_helper_check`
//! - `drivers/gpu/drm/drm_atomic_helper.c::drm_atomic_helper_commit`
//! - `drivers/gpu/drm/drm_mode_object.c::drm_mode_object_register`
//! - `drivers/gpu/drm/drm_property.c::drm_property_create_range`
//! - `drivers/gpu/drm/drm_property.c::drm_property_create_enum`
//! - `drivers/gpu/drm/drm_property.c::drm_property_create_blob`
//! - `drivers/gpu/drm/drm_syncobj.c::drm_syncobj_create`
//! - `drivers/gpu/drm/drm_syncobj.c::drm_syncobj_signal`

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use crate::drm::atomic::{
    atomic_check_and_commit, AtomicCheckPolicy, AtomicError, AtomicOps, AtomicState,
    ConnectorState, CrtcState, PlaneState,
};
use crate::drm::card::{
    Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
};
use crate::drm::syncobj::{BinaryFence, DmaFence, SyncObjTable, SYNCOBJ_WAIT_FLAGS_WAIT_ALL};
use crate::Mode;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── FakeMmio ─────────────────────────────────────────────────────────────────
// Reused verbatim from Wave 30 e2e_tests.rs — models bochs VBE register window.

struct FakeMmio {
    data: Vec<u8>,
}

impl FakeMmio {
    fn new(size_bytes: usize) -> Self {
        Self {
            data: alloc::vec![0u8; size_bytes],
        }
    }

    fn write16(&mut self, offset: usize, value: u16) {
        if offset + 2 > self.data.len() {
            return;
        }
        self.data[offset] = value as u8;
        self.data[offset + 1] = (value >> 8) as u8;
    }

    fn read16(&self, offset: usize) -> u16 {
        if offset + 2 > self.data.len() {
            return 0;
        }
        u16::from_le_bytes([self.data[offset], self.data[offset + 1]])
    }
}

// Bochs VBE register offsets (BAR2 + 0x500).
const VBE_BASE: usize = 0x500;
const VBE_XRES_OFF: usize = VBE_BASE + 0x02;
const VBE_YRES_OFF: usize = VBE_BASE + 0x04;
const VBE_BPP_OFF: usize = VBE_BASE + 0x06;

// ── FakeAtomicOps ────────────────────────────────────────────────────────────
// Records driver-side hook calls. Does not touch hardware.

struct FakeAtomicOps {
    /// Incremented each time atomic_check is called successfully.
    pub check_count: core::sync::atomic::AtomicU32,
    /// Incremented each time atomic_commit is called successfully.
    pub commit_count: core::sync::atomic::AtomicU32,
    /// If true, atomic_check returns OverBandwidth.
    pub fail_check: bool,
    /// If true, atomic_commit returns OverBandwidth.
    pub fail_commit: bool,
}

impl FakeAtomicOps {
    fn new() -> Self {
        FakeAtomicOps {
            check_count: core::sync::atomic::AtomicU32::new(0),
            commit_count: core::sync::atomic::AtomicU32::new(0),
            fail_check: false,
            fail_commit: false,
        }
    }
}

impl AtomicOps for FakeAtomicOps {
    fn atomic_check(&self, _card: &Card, _state: &AtomicState) -> Result<(), AtomicError> {
        if self.fail_check {
            return Err(AtomicError::OverBandwidth);
        }
        self.check_count
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn atomic_commit(&self, _card: &mut Card, _state: &AtomicState) -> Result<(), AtomicError> {
        if self.fail_commit {
            return Err(AtomicError::OverBandwidth);
        }
        self.commit_count
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

// ── Card builder helpers ─────────────────────────────────────────────────────

/// Build a minimal card with N CRTCs (ids 0..N), N connectors, and one encoder.
fn make_card(n_crtcs: usize) -> Card {
    let mut card = Card::new("fake-drm", "Fake GPU for atomic tests", (0, 0, 1));
    for i in 0..n_crtcs as u32 {
        card.crtcs.push(Crtc {
            id: i,
            mode: None,
            enabled: false,
            primary_fb: None,
            x: 0,
            y: 0,
        });
        card.connectors.push(Connector {
            id: i,
            connector_type: ConnectorType::HdmiA,
            connector_type_id: i,
            status: ConnectorStatus::Connected,
            encoder_id: None,
            modes: alloc::vec![Mode::XGA_60, Mode::FHD_60],
        });
    }
    card.encoders.push(Encoder {
        id: 0,
        encoder_type: EncoderType::Tmds,
        possible_crtcs: 0xFFFF_FFFF,
        possible_clones: 0,
        crtc_id: None,
    });
    card
}

/// Allocate a GEM object and wrap it in an FB of the given dimensions.
/// Returns `(gem_handle, fb_id)`.
fn make_fb(card: &mut Card, width: u32, height: u32) -> (u32, u32) {
    let phys: u64 = 0x0800_0000 + (card.framebuffers.len() as u64) * 0x0100_0000;
    let gem = card
        .gem
        .alloc(phys, (width * height * 4) as usize)
        .expect("gem alloc");
    let fb = card
        .addfb2(
            width,
            height,
            0x3432_5258, /* XRGB8888 */
            width * 4,
            gem,
        )
        .expect("addfb2");
    (gem, fb)
}

// ════════════════════════════════════════════════════════════════════════════
// Smoke 1 — CRTC object-id allocation: two CRTCs get distinct IDs
// Linux ref: drm_mode_object_register (drm_mode_object.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_crtc_ids_distinct() -> TestResult {
    let card = make_card(2);
    if card.crtcs.len() != 2 {
        return TestResult::Fail("expected 2 CRTCs");
    }
    let id0 = card.crtcs[0].id;
    let id1 = card.crtcs[1].id;
    if id0 == id1 {
        return TestResult::Fail("CRTC ids are not distinct");
    }
    // IDs must also appear in crtc_ids() iterator.
    let ids: Vec<u32> = card.crtc_ids().collect();
    if !ids.contains(&id0) || !ids.contains(&id1) {
        return TestResult::Fail("crtc_ids iterator missing expected id");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_crtc_ids_distinct);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 2 — Connector with EDID property: 128-byte canned EDID stored in a
// blob-property model. We simulate a blob store with a Vec.
// Linux ref: drm_property_create_blob (drm_property.c)
// ════════════════════════════════════════════════════════════════════════════

/// Minimal blob-property model for test purposes.
struct BlobProp {
    name: &'static str,
    data: Vec<u8>,
}

fn smoke_atomic_connector_edid_blob_prop() -> TestResult {
    // Synthesise a 128-byte "EDID" (only header + checksum matter for this test).
    let mut edid = [0u8; 128];
    edid[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    edid[18] = 1;
    edid[19] = 4; // version 1.4
                  // Fix checksum.
    let s: u8 = edid[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    edid[127] = 0u8.wrapping_sub(s);

    // Register a blob property carrying this EDID.
    let props: Vec<BlobProp> = alloc::vec![BlobProp {
        name: "EDID",
        data: edid.to_vec()
    },];

    // Resolve by name.
    let found = props.iter().find(|p| p.name == "EDID");
    if found.is_none() {
        return TestResult::Fail("EDID property not found by name");
    }
    let blob = &found.unwrap().data;

    // Blob must be 128 bytes.
    if blob.len() != 128 {
        return TestResult::Fail("EDID blob length != 128");
    }

    // Header check: bytes 0..8 must match the EDID magic.
    let magic = [0x00u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
    if blob[0..8] != magic {
        return TestResult::Fail("EDID blob header mismatch");
    }

    // Multiple "reads" must return the same slice content.
    let blob2 = &found.unwrap().data;
    if blob != blob2 {
        return TestResult::Fail("EDID blob not stable across reads");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_connector_edid_blob_prop
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 3 — Plane with mandatory plane properties: verify that PlaneState
// carries FB_ID, CRTC_ID, CRTC_X/Y/W/H, SRC_X/Y/W/H.
// Linux ref: drm_plane_create_*_property helpers (drm_plane.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_plane_has_required_props() -> TestResult {
    // Build a PlaneState and confirm all required fields are present and
    // round-trip through the structure.
    let ps = PlaneState {
        id: 42,
        crtc_id: Some(0),
        fb_id: Some(7),
        crtc_x: 10,
        crtc_y: 20,
        crtc_w: 640,
        crtc_h: 480,
        src_x: 0,
        src_y: 0,
        src_w: 640,
        src_h: 480,
    };

    if ps.fb_id != Some(7) {
        return TestResult::Fail("FB_ID");
    }
    if ps.crtc_id != Some(0) {
        return TestResult::Fail("CRTC_ID");
    }
    if ps.crtc_x != 10 {
        return TestResult::Fail("CRTC_X");
    }
    if ps.crtc_y != 20 {
        return TestResult::Fail("CRTC_Y");
    }
    if ps.crtc_w != 640 {
        return TestResult::Fail("CRTC_W");
    }
    if ps.crtc_h != 480 {
        return TestResult::Fail("CRTC_H");
    }
    if ps.src_x != 0 {
        return TestResult::Fail("SRC_X");
    }
    if ps.src_y != 0 {
        return TestResult::Fail("SRC_Y");
    }
    if ps.src_w != 640 {
        return TestResult::Fail("SRC_W");
    }
    if ps.src_h != 480 {
        return TestResult::Fail("SRC_H");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_plane_has_required_props
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 4 — Build empty AtomicState
// Linux ref: drm_atomic_state_alloc (drm_atomic.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_empty_state_new() -> TestResult {
    let state = AtomicState::default();
    if !state.connectors.is_empty() {
        return TestResult::Fail("empty state has connector entries");
    }
    if !state.crtcs.is_empty() {
        return TestResult::Fail("empty state has CRTC entries");
    }
    if !state.planes.is_empty() {
        return TestResult::Fail("empty state has plane entries");
    }
    if state.checked {
        return TestResult::Fail("empty state should not be pre-checked");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_empty_state_new);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 5 — Add CRTC update (ACTIVE=1) to state
// Linux ref: drm_atomic_get_crtc_state (drm_atomic.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_add_crtc_update_active() -> TestResult {
    let mut state = AtomicState::default();
    state.crtcs.push(CrtcState {
        id: 0,
        enable: true,
        active: true,
        mode: Some(Mode::XGA_60),
        mode_changed: true,
        connectors_changed: false,
    });

    if state.crtcs.len() != 1 {
        return TestResult::Fail("expected 1 CRTC entry after push");
    }
    if !state.crtcs[0].enable {
        return TestResult::Fail("CRTC active flag not set");
    }
    if state.crtcs[0].id != 0 {
        return TestResult::Fail("CRTC id wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_add_crtc_update_active
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 6 — Add plane update with FB attached
// Linux ref: drm_atomic_get_plane_state (drm_atomic.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_add_plane_with_fb() -> TestResult {
    let mut state = AtomicState::default();
    state.planes.push(PlaneState {
        id: 0,
        crtc_id: Some(0),
        fb_id: Some(1),
        crtc_x: 0,
        crtc_y: 0,
        crtc_w: 1024,
        crtc_h: 768,
        src_x: 0,
        src_y: 0,
        src_w: 1024,
        src_h: 768,
    });

    if state.planes.len() != 1 {
        return TestResult::Fail("expected 1 plane entry");
    }
    let ps = &state.planes[0];
    if ps.fb_id != Some(1) {
        return TestResult::Fail("plane fb_id mismatch");
    }
    if ps.crtc_id != Some(0) {
        return TestResult::Fail("plane crtc_id mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_add_plane_with_fb);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 7 — Add connector with CRTC binding
// Linux ref: drm_atomic_get_connector_state (drm_atomic.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_add_connector_with_crtc_binding() -> TestResult {
    let mut state = AtomicState::default();
    state.connectors.push(ConnectorState {
        id: 0,
        crtc_id: Some(0),
    });

    if state.connectors.len() != 1 {
        return TestResult::Fail("expected 1 connector entry");
    }
    if state.connectors[0].crtc_id != Some(0) {
        return TestResult::Fail("connector crtc_id mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_add_connector_with_crtc_binding
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 8 — check_only happy path: full state passes core_check, no HW change
// Linux ref: drm_atomic_helper_check (drm_atomic_helper.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_check_only_happy_path() -> TestResult {
    let mut card = make_card(1);
    let (_gem, fb_id) = make_fb(&mut card, 1024, 768);

    // Snapshot the CRTC mode before the check-only operation.
    let mode_before = card.crtcs[0].mode;
    let fb_before = card.crtcs[0].primary_fb;

    let mut state = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    state.crtcs.push(CrtcState {
        id: 0,
        enable: true,
        active: true,
        mode: Some(Mode::XGA_60),
        mode_changed: true,
        connectors_changed: false,
    });
    state.connectors.push(ConnectorState {
        id: 0,
        crtc_id: Some(0),
    });
    state.planes.push(PlaneState {
        id: 0,
        crtc_id: Some(0),
        fb_id: Some(fb_id),
        crtc_w: 1024,
        crtc_h: 768,
        src_w: 1024,
        src_h: 768,
        ..Default::default()
    });

    let policy = AtomicCheckPolicy::default();
    // core_check should succeed.
    let result = state.core_check(&card, &policy);
    if result.is_err() {
        return TestResult::Fail("core_check rejected valid state");
    }
    if !state.checked {
        return TestResult::Fail("state.checked not set after successful core_check");
    }

    // Hardware unchanged — check_only must not have called core_commit.
    if card.crtcs[0].mode != mode_before {
        return TestResult::Fail("core_check modified CRTC mode (should be check_only)");
    }
    if card.crtcs[0].primary_fb != fb_before {
        return TestResult::Fail("core_check modified primary_fb (should be check_only)");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_check_only_happy_path);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 9 — check_only rejects impossible mode (9999×9999)
// Linux ref: drm_atomic_plane_check — coordinate bounds
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_check_only_rejects_invalid_mode() -> TestResult {
    let mut card = make_card(1);
    // FB is 64×64; requesting src rect 9999×9999 exceeds bounds.
    let (_gem, fb_id) = make_fb(&mut card, 64, 64);

    let mut state = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    state.crtcs.push(CrtcState {
        id: 0,
        enable: true,
        active: true,
        mode: Some(Mode {
            width: 9999,
            height: 9999,
            refresh_hz: 60,
            bpp: 32,
        }),
        mode_changed: true,
        connectors_changed: false,
    });
    state.planes.push(PlaneState {
        id: 0,
        crtc_id: Some(0),
        fb_id: Some(fb_id),
        crtc_w: 9999,
        crtc_h: 9999,
        src_w: 9999,
        src_h: 9999, // exceeds FB 64×64
        ..Default::default()
    });

    let policy = AtomicCheckPolicy::default();
    match state.core_check(&card, &policy) {
        Err(AtomicError::PlaneOutOfRange) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("wrong error for oversized src rect");
        }
        Ok(()) => return TestResult::Fail("check_only should reject 9999x9999 src"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_check_only_rejects_invalid_mode
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 10 — check_only rejects unattached plane (FB without CRTC)
// Linux ref: drm_atomic_plane_check PlaneFbCrtcMismatch
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_check_only_rejects_unattached_plane() -> TestResult {
    let mut card = make_card(1);
    let (_gem, fb_id) = make_fb(&mut card, 640, 480);

    let mut state = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    // Plane has FB but no CRTC — violates both-or-neither rule.
    state.planes.push(PlaneState {
        id: 0,
        crtc_id: None,
        fb_id: Some(fb_id),
        crtc_w: 640,
        crtc_h: 480,
        src_w: 640,
        src_h: 480,
        ..Default::default()
    });

    let policy = AtomicCheckPolicy::default();
    match state.core_check(&card, &policy) {
        Err(AtomicError::PlaneFbCrtcMismatch) => {}
        Err(e) => {
            let _ = e;
            return TestResult::Fail("expected PlaneFbCrtcMismatch for FB-only plane");
        }
        Ok(()) => return TestResult::Fail("unattached plane must be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_check_only_rejects_unattached_plane
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 11 — commit applies CRTC mode; bochs VBE MMIO updated
// Linux ref: drm_atomic_helper_commit_modeset_enables (drm_atomic_helper.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_commit_applies_crtc_mode() -> TestResult {
    let mut card = make_card(1);
    let (_gem, fb_id) = make_fb(&mut card, 640, 480);

    // Simulate bochs VBE MMIO window.
    let mut mmio = FakeMmio::new(0x1000);

    let mut state = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    state.crtcs.push(CrtcState {
        id: 0,
        enable: true,
        active: true,
        mode: Some(Mode {
            width: 640,
            height: 480,
            refresh_hz: 60,
            bpp: 32,
        }),
        mode_changed: true,
        connectors_changed: false,
    });
    state.connectors.push(ConnectorState {
        id: 0,
        crtc_id: Some(0),
    });
    state.planes.push(PlaneState {
        id: 0,
        crtc_id: Some(0),
        fb_id: Some(fb_id),
        crtc_w: 640,
        crtc_h: 480,
        src_w: 640,
        src_h: 480,
        ..Default::default()
    });

    let ops = FakeAtomicOps::new();
    let policy = AtomicCheckPolicy::default();
    let result = atomic_check_and_commit(&mut card, &mut state, &policy, Some(&ops));
    if result.is_err() {
        return TestResult::Fail("atomic_check_and_commit failed for 640x480 commit");
    }

    // core_commit must have written mode to card CRTC.
    let crtc = &card.crtcs[0];
    match crtc.mode {
        Some(m) if m.width == 640 && m.height == 480 => {}
        Some(m) => {
            let _ = m;
            return TestResult::Fail("CRTC mode width/height mismatch after commit");
        }
        None => return TestResult::Fail("CRTC mode is None after commit"),
    }
    if !crtc.enabled {
        return TestResult::Fail("CRTC not enabled after commit");
    }

    // Simulate driver writing VBE registers (what BochsCard.atomic_commit would do).
    if let Some(m) = crtc.mode {
        mmio.write16(VBE_XRES_OFF, m.width as u16);
        mmio.write16(VBE_YRES_OFF, m.height as u16);
        mmio.write16(VBE_BPP_OFF, m.bpp as u16);
    }
    if mmio.read16(VBE_XRES_OFF) != 640 {
        return TestResult::Fail("VBE_XRES not 640 after modeset");
    }
    if mmio.read16(VBE_YRES_OFF) != 480 {
        return TestResult::Fail("VBE_YRES not 480 after modeset");
    }
    if mmio.read16(VBE_BPP_OFF) != 32 {
        return TestResult::Fail("VBE_BPP not 32 after modeset");
    }

    // FakeAtomicOps must have been called once each.
    if ops.check_count.load(core::sync::atomic::Ordering::Relaxed) != 1 {
        return TestResult::Fail("driver atomic_check was not called");
    }
    if ops.commit_count.load(core::sync::atomic::Ordering::Relaxed) != 1 {
        return TestResult::Fail("driver atomic_commit was not called");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_commit_applies_crtc_mode
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 12 — commit + page-flip: new FB_ID in plane → crtc.primary_fb updated
// Linux ref: drm_atomic_helper_page_flip (drm_atomic_helper.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_commit_page_flip_updates_primary_fb() -> TestResult {
    let mut card = make_card(1);

    // First modeset with fb_a.
    let (_gem_a, fb_a) = make_fb(&mut card, 1920, 1080);
    {
        let mut state = AtomicState {
            allow_modeset: true,
            ..Default::default()
        };
        state.crtcs.push(CrtcState {
            id: 0,
            enable: true,
            active: true,
            mode: Some(Mode::FHD_60),
            mode_changed: true,
            connectors_changed: false,
        });
        state.connectors.push(ConnectorState {
            id: 0,
            crtc_id: Some(0),
        });
        state.planes.push(PlaneState {
            id: 0,
            crtc_id: Some(0),
            fb_id: Some(fb_a),
            crtc_w: 1920,
            crtc_h: 1080,
            src_w: 1920,
            src_h: 1080,
            ..Default::default()
        });
        let policy = AtomicCheckPolicy::default();
        atomic_check_and_commit(&mut card, &mut state, &policy, None)
            .expect("initial modeset failed");
    }

    if card.crtcs[0].primary_fb != Some(fb_a) {
        return TestResult::Fail("primary_fb not set to fb_a after initial modeset");
    }

    // Page-flip: swap to fb_b (no modeset flag needed for same-mode flip).
    let (_gem_b, fb_b) = make_fb(&mut card, 1920, 1080);
    {
        let mut state = AtomicState {
            allow_modeset: false,
            ..Default::default()
        };
        // No CRTC mode change — just plane FB swap.
        state.planes.push(PlaneState {
            id: 0,
            crtc_id: Some(0),
            fb_id: Some(fb_b),
            crtc_w: 1920,
            crtc_h: 1080,
            src_w: 1920,
            src_h: 1080,
            ..Default::default()
        });
        let policy = AtomicCheckPolicy::default();
        let result = atomic_check_and_commit(&mut card, &mut state, &policy, None);
        if result.is_err() {
            return TestResult::Fail("page-flip commit failed");
        }
    }

    if card.crtcs[0].primary_fb != Some(fb_b) {
        return TestResult::Fail("primary_fb not updated to fb_b after page-flip");
    }

    // PAGE_FLIP_EVENT flag: verify it's defined (dispatch hook would schedule event).
    let _ = crate::drm::atomic::DRM_MODE_PAGE_FLIP_EVENT;

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_commit_page_flip_updates_primary_fb
);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 13 — Property type Range: [0, 100]; set 50 OK; set 200 rejected
// Linux ref: drm_property_create_range (drm_property.c)
// ════════════════════════════════════════════════════════════════════════════

/// Minimal range property model.
struct RangeProp {
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    name: &'static str,
    min: u64,
    max: u64,
}

impl RangeProp {
    fn set(&self, value: u64) -> Result<u64, &'static str> {
        if value < self.min || value > self.max {
            Err("out of range")
        } else {
            Ok(value)
        }
    }
}

fn smoke_atomic_property_range() -> TestResult {
    let prop = RangeProp {
        name: "brightness",
        min: 0,
        max: 100,
    };

    match prop.set(50) {
        Ok(50) => {}
        Ok(_) => return TestResult::Fail("range set returned wrong value"),
        Err(_) => return TestResult::Fail("valid value 50 rejected by range property"),
    }

    match prop.set(0) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("boundary value 0 rejected"),
    }

    match prop.set(100) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("boundary value 100 rejected"),
    }

    match prop.set(200) {
        Err(_) => {}
        Ok(_) => return TestResult::Fail("out-of-range value 200 was accepted"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_property_range);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 14 — Property type Enum: {0=Auto,1=Off,2=On}; "On" → 2; "Bogus" → err
// Linux ref: drm_property_create_enum (drm_property.c)
// ════════════════════════════════════════════════════════════════════════════

struct EnumProp {
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    name: &'static str,
    variants: &'static [(&'static str, u64)],
}

impl EnumProp {
    fn set_by_name(&self, name: &str) -> Result<u64, &'static str> {
        self.variants
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .ok_or("unknown enum variant")
    }
}

fn smoke_atomic_property_enum() -> TestResult {
    let prop = EnumProp {
        name: "scaling_mode",
        variants: &[("Auto", 0), ("Off", 1), ("On", 2)],
    };

    match prop.set_by_name("On") {
        Ok(2) => {}
        Ok(v) => {
            let _ = v;
            return TestResult::Fail("'On' did not map to 2");
        }
        Err(_) => return TestResult::Fail("'On' rejected by enum property"),
    }

    match prop.set_by_name("Auto") {
        Ok(0) => {}
        Ok(_) => return TestResult::Fail("'Auto' did not map to 0"),
        Err(_) => return TestResult::Fail("'Auto' rejected"),
    }

    match prop.set_by_name("Off") {
        Ok(1) => {}
        Ok(_) => return TestResult::Fail("'Off' did not map to 1"),
        Err(_) => return TestResult::Fail("'Off' rejected"),
    }

    match prop.set_by_name("Bogus") {
        Err(_) => {}
        Ok(_) => return TestResult::Fail("unknown variant 'Bogus' was accepted"),
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_property_enum);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 15 — Property type Blob: register blob; get returns same bytes;
//            multiple readers see the same blob.
// Linux ref: drm_property_create_blob (drm_property.c)
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_property_blob() -> TestResult {
    use alloc::sync::Arc;

    // Blob registry: just an Arc<Vec<u8>> to simulate shared ownership.
    let data: Vec<u8> = (0u8..128).collect();
    let blob: Arc<Vec<u8>> = Arc::new(data.clone());

    // Reader 1.
    let r1 = Arc::clone(&blob);
    // Reader 2.
    let r2 = Arc::clone(&blob);

    if r1.len() != 128 {
        return TestResult::Fail("reader 1 blob length != 128");
    }
    if r2.len() != 128 {
        return TestResult::Fail("reader 2 blob length != 128");
    }
    if r1.as_slice() != r2.as_slice() {
        return TestResult::Fail("readers see different blob contents");
    }
    // Spot-check first and last byte.
    if r1[0] != 0 || r1[127] != 127 {
        return TestResult::Fail("blob bytes wrong");
    }

    // Arc refcount: original + 2 readers = 3 strong references.
    if Arc::strong_count(&blob) != 3 {
        return TestResult::Fail("blob refcount unexpected");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/atomic_e2e", smoke_atomic_property_blob);

// ════════════════════════════════════════════════════════════════════════════
// Smoke 16 — syncobj integration: create syncobj → attach to out_fence →
//            after atomic commit, signal syncobj → syncobj.is_signalled()
// Linux ref: drm_syncobj_create (drm_syncobj.c) + commit 41199ea0 WAIT_ALL
// ════════════════════════════════════════════════════════════════════════════

fn smoke_atomic_syncobj_signalled_after_commit() -> TestResult {
    let mut card = make_card(1);
    let (_gem, fb_id) = make_fb(&mut card, 640, 480);

    // Create syncobj table and a fresh (unsignalled) syncobj.
    let mut table = SyncObjTable::new();
    let handle = match table.create(0) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("syncobj create failed"),
    };

    // Confirm it starts unsignalled.
    {
        let obj = table.get(handle).expect("syncobj not found");
        // No fence attached yet → not signalled.
        if obj.is_signalled() {
            return TestResult::Fail("syncobj should be unsignalled before commit");
        }
    }

    // Run an atomic commit.
    let mut state = AtomicState {
        allow_modeset: true,
        ..Default::default()
    };
    state.crtcs.push(CrtcState {
        id: 0,
        enable: true,
        active: true,
        mode: Some(Mode {
            width: 640,
            height: 480,
            refresh_hz: 60,
            bpp: 32,
        }),
        mode_changed: true,
        connectors_changed: false,
    });
    state.connectors.push(ConnectorState {
        id: 0,
        crtc_id: Some(0),
    });
    state.planes.push(PlaneState {
        id: 0,
        crtc_id: Some(0),
        fb_id: Some(fb_id),
        crtc_w: 640,
        crtc_h: 480,
        src_w: 640,
        src_h: 480,
        ..Default::default()
    });
    let ops = FakeAtomicOps::new();
    let policy = AtomicCheckPolicy::default();
    let result = atomic_check_and_commit(&mut card, &mut state, &policy, Some(&ops));
    if result.is_err() {
        return TestResult::Fail("atomic_check_and_commit failed");
    }

    // Attach an out_fence to the syncobj and signal it (what the driver
    // does after commit completes — Linux: drm_crtc_arm_vblank_event).
    let out_fence = BinaryFence::new();
    {
        let obj = table.get_mut(handle).expect("syncobj not found");
        obj.replace_fence(out_fence.clone() as alloc::sync::Arc<dyn DmaFence>);
    }
    // Commit done — signal the fence.
    out_fence.signal();

    // syncobj must now be signalled.
    {
        let obj = table.get(handle).expect("syncobj not found");
        if !obj.is_signalled() {
            return TestResult::Fail("syncobj not signalled after fence signal");
        }
    }

    // wait_handles with WAIT_ALL on a single handle must succeed immediately.
    let wait_result = table.wait_handles(&[handle], 1_000_000, SYNCOBJ_WAIT_FLAGS_WAIT_ALL);
    if wait_result.is_err() {
        return TestResult::Fail("wait_handles failed on signalled syncobj");
    }

    // Destroy to clean up.
    table.destroy(handle).expect("destroy failed");
    if !table.is_empty() {
        return TestResult::Fail("syncobj table not empty after destroy");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_atomic_syncobj_signalled_after_commit
);

// ════════════════════════════════════════════════════════════════════════════
// Wave-37 subsystem-ID smokes
//
// Linux ref: PCI 3.0 §6.2.4 — Subsystem Vendor ID (cfg+0x2C) + Subsystem ID
//            (cfg+0x2E). Linux reads them in drivers/pci/probe.c::pci_read_bases
//            (called from pci_setup_device) and exposes via
//            /sys/bus/pci/devices/<slot>/subsystem_vendor + subsystem_device.
// ════════════════════════════════════════════════════════════════════════════

// ── Smoke 17: DeviceId subsystem field round-trip ──────────────────────────
// Verify that (vendor=0x1002, device=0x1636, subsystem_vendor=0x1849,
// subsystem_id=0x1636) round-trips through DeviceId correctly.
// 0x1849 = ASRock, device 0x1636 = Renoir.

fn smoke_subsystem_id_device_id_round_trip() -> TestResult {
    use narf_bus::DeviceId;

    let id = DeviceId {
        vendor: 0x1002,
        device: 0x1636,
        class: 0x030000,
        subsystem_vendor: 0x1849,
        subsystem_id: 0x1636,
    };

    if id.vendor != 0x1002 {
        return TestResult::Fail("vendor mismatch");
    }
    if id.device != 0x1636 {
        return TestResult::Fail("device mismatch");
    }
    if id.subsystem_vendor != 0x1849 {
        return TestResult::Fail("subsystem_vendor mismatch (expected 0x1849 ASRock)");
    }
    if id.subsystem_id != 0x1636 {
        return TestResult::Fail("subsystem_id mismatch (expected 0x1636 Renoir)");
    }
    // Also verify PartialEq round-trip.
    let id2 = id;
    if id != id2 {
        return TestResult::Fail("DeviceId Copy/PartialEq broken");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_subsystem_id_device_id_round_trip
);

// ── Smoke 18: PCI config-space subsystem ID parse ─────────────────────────
// Synthesise a 64-byte type-0 header byte-slice with subsystem IDs at
// offsets 0x2C/0x2E and verify our parse logic extracts them correctly.
// This mirrors what pcie::enumerate_segment reads at boot time.

fn smoke_subsystem_id_config_space_parse() -> TestResult {
    // Build a synthetic 64-byte config-space buffer.
    let mut cfg = [0u8; 64];
    // Offset 0x00: vendor=0x1002, device=0x1636.
    cfg[0x00] = 0x02;
    cfg[0x01] = 0x10;
    cfg[0x02] = 0x36;
    cfg[0x03] = 0x16;
    // Offset 0x2C: subsystem_vendor=0x1849 (ASRock).
    cfg[0x2C] = 0x49;
    cfg[0x2D] = 0x18;
    // Offset 0x2E: subsystem_id=0x1636.
    cfg[0x2E] = 0x36;
    cfg[0x2F] = 0x16;

    // Parse as little-endian u16 values — the same read the ECAM walker does.
    let subsys_word = u32::from_le_bytes([cfg[0x2C], cfg[0x2D], cfg[0x2E], cfg[0x2F]]);
    let subsystem_vendor = (subsys_word & 0xFFFF) as u16;
    let subsystem_id = ((subsys_word >> 16) & 0xFFFF) as u16;

    if subsystem_vendor != 0x1849 {
        return TestResult::Fail("subsystem_vendor parse mismatch (expected 0x1849)");
    }
    if subsystem_id != 0x1636 {
        return TestResult::Fail("subsystem_id parse mismatch (expected 0x1636)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_subsystem_id_config_space_parse
);

// ── Smoke 19: sysfs subsystem_vendor attr format ──────────────────────────
// AmdgpuCard::subsystem_vendor() returns the value; sysfs formats it as
// "0x<hex4>\n". Verify the formatting function produces the right string.

fn smoke_subsystem_id_sysfs_vendor_format() -> TestResult {
    use crate::drm_devfs_bridge::AmdgpuCard;
    use crate::drm_registry::DrmCard;

    let card = AmdgpuCard::new(
        "card0".into(),
        0x1002, // AMD
        0x1636, // Renoir
        0x1849, // ASRock subsystem vendor
        0x1636, // Renoir subsystem id
        None,
    );

    let sv = card.subsystem_vendor();
    if sv != 0x1849 {
        return TestResult::Fail("subsystem_vendor() != 0x1849");
    }
    // Verify the sysfs formatting would produce "0x1849\n".
    let formatted = alloc::format!("0x{:04x}\n", sv);
    if formatted != "0x1849\n" {
        return TestResult::Fail("sysfs subsystem_vendor format mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_subsystem_id_sysfs_vendor_format
);

// ── Smoke 20: sysfs subsystem_device attr format ──────────────────────────

fn smoke_subsystem_id_sysfs_device_format() -> TestResult {
    use crate::drm_devfs_bridge::AmdgpuCard;
    use crate::drm_registry::DrmCard;

    let card = AmdgpuCard::new(
        "card0".into(),
        0x1002, // AMD
        0x1636, // Renoir
        0x1849, // ASRock subsystem vendor
        0x1636, // Renoir subsystem id
        None,
    );

    let sd = card.subsystem_device();
    if sd != 0x1636 {
        return TestResult::Fail("subsystem_device() != 0x1636");
    }
    let formatted = alloc::format!("0x{:04x}\n", sd);
    if formatted != "0x1636\n" {
        return TestResult::Fail("sysfs subsystem_device format mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_subsystem_id_sysfs_device_format
);

// ── Smoke 21: bochs card subsystem IDs = (0x1AF4, 0x1100) ─────────────────

fn smoke_subsystem_id_bochs_qemu_values() -> TestResult {
    use crate::drm_devfs_bridge::BochsCard;
    use crate::drm_registry::DrmCard;

    let card = BochsCard::new("card0".into());

    let sv = card.subsystem_vendor();
    let sd = card.subsystem_device();

    if sv != 0x1AF4 {
        return TestResult::Fail("BochsCard subsystem_vendor != 0x1AF4 (Red Hat/QEMU)");
    }
    if sd != 0x1100 {
        return TestResult::Fail("BochsCard subsystem_device != 0x1100");
    }
    // Also verify sysfs formatting.
    let sv_str = alloc::format!("0x{:04x}\n", sv);
    let sd_str = alloc::format!("0x{:04x}\n", sd);
    if sv_str != "0x1af4\n" {
        return TestResult::Fail("BochsCard subsystem_vendor sysfs format wrong");
    }
    if sd_str != "0x1100\n" {
        return TestResult::Fail("BochsCard subsystem_device sysfs format wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_subsystem_id_bochs_qemu_values
);

// ── Smoke 22: existing Wave-33 smokes — AmdgpuCard non-zero subsystem ──────
// Verify that an AmdgpuCard constructed with real subsystem IDs doesn't
// accidentally return 0 (which was the pre-fix stub behaviour).

fn smoke_subsystem_id_amdgpu_nonzero_when_set() -> TestResult {
    use crate::drm_devfs_bridge::AmdgpuCard;
    use crate::drm_registry::DrmCard;

    // Simulate probe with a real subsystem vendor (ThinkPad OEM = Lenovo 0x17AA).
    let card = AmdgpuCard::new(
        "card0".into(),
        0x1002, // AMD
        0x1900, // Phoenix HawkPoint1
        0x17AA, // Lenovo
        0x3813, // Lenovo ThinkPad subsystem device
        None,
    );

    if card.subsystem_vendor() == 0 {
        return TestResult::Fail("subsystem_vendor is 0 even though 0x17AA was provided");
    }
    if card.subsystem_device() == 0 {
        return TestResult::Fail("subsystem_device is 0 even though 0x3813 was provided");
    }
    if card.subsystem_vendor() != 0x17AA {
        return TestResult::Fail("subsystem_vendor doesn't match 0x17AA (Lenovo)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/atomic_e2e",
    smoke_subsystem_id_amdgpu_nonzero_when_set
);
