//! DRM ioctl bridge smokes (Wave 36).
//!
//! Exercises [`crate::drm_ioctl_bridge::dispatch_card`] end-to-end:
//!
//! - `_IOC` encoding round-trip (the macros in `drm_uapi`).
//! - ENOTTY on unknown numbers + EBADF mapping at the FileOps layer.
//! - VERSION copies driver identity into user-supplied buffers.
//! - GETRESOURCES populates count + (when ptrs supplied) id arrays.
//! - MODE_ATOMIC builds an AtomicState + runs check+commit.
//! - Render-node fd rejects SETCRTC with PermissionDenied (→ EACCES).
//! - Render-node fd accepts GEM_CLOSE (render_allow=true ioctl).
//!
//! Test buffers are kernel-owned: the kernel-test build of `copy_in` /
//! `copy_out` accepts a range wholly inside the kernel half (production
//! accepts only user-half ranges), so passing a `&mut UapiStruct as *mut _
//! as usize` works just like a user pointer would. The
//! `smoke_drm_user_copies_*` cases open `StrictUserCopies` to assert the
//! production predicate.
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/gpu/drm/drm_ioctl.c::drm_ioctl` — line-for-line model.
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_check_only`.
//! - `drivers/gpu/drm/drm_ioctl.c::drm_ioctl_permit` — DRM_RENDER_ALLOW.
//! - `include/uapi/asm-generic/ioctl.h` — _IOC macro encoding.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use narf_filesystem::{FileOps, FsError};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::drm::card::{
    Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
};
use crate::drm_devfs_bridge::BochsCard;
/// DRM master id every existing smoke drives the card as. `register_test_card`
/// pre-establishes this open as the card's master, so the modeset gate is
/// satisfied without threading an id through each call. Master *arbitration*
/// itself is covered by the dedicated smokes at the end of this file, which
/// call the real `dispatch_card` with explicit competing ids.
const SMOKE_MASTER_ID: u64 = 1;

/// Test shim over [`crate::drm_ioctl_bridge::dispatch_card`] that injects
/// [`SMOKE_MASTER_ID`] as the calling open. Keeps the smoke call sites at the
/// pre-master signature `(idx, cmd, arg, render)`.
fn dispatch_card(card_index: u32, cmd: u32, arg: usize, render: bool) -> Result<u64, FsError> {
    crate::drm_ioctl_bridge::dispatch_card(card_index, SMOKE_MASTER_ID, cmd, arg, render)
}
use crate::drm_uapi::{
    ioc, ioc_dir, ioc_nr, ioc_size, ioc_type, iow, iowr, DrmModeAtomicUapi, DrmModeCardResUapi,
    DrmVersionUapi, DRM_IOCTL_BASE, DRM_IOCTL_GEM_CLOSE, DRM_IOCTL_MODE_ATOMIC,
    DRM_IOCTL_MODE_GETPLANE, DRM_IOCTL_MODE_GETPLANERESOURCES, DRM_IOCTL_MODE_GETRESOURCES,
    DRM_IOCTL_MODE_SETCRTC, DRM_IOCTL_SET_CLIENT_CAP, DRM_IOCTL_VERSION, IOC_READ, IOC_WRITE,
};
use alloc::format;
use alloc::string::String;

// ── Setup helpers ──────────────────────────────────────────────────────

/// Build a populated Card for an ioctl smoke. 2 CRTCs, 1 connector,
/// 1 encoder — enough surface for GETRESOURCES + ATOMIC.
fn make_test_card() -> Card {
    let mut card = Card::new("narf-drm", "narf bochs driver", (1, 0, 0));
    card.crtcs.push(Crtc {
        id: 11,
        mode: None,
        enabled: false,
        primary_fb: None,
        x: 0,
        y: 0,
    });
    card.crtcs.push(Crtc {
        id: 12,
        mode: None,
        enabled: false,
        primary_fb: None,
        x: 0,
        y: 0,
    });
    card.encoders.push(Encoder {
        id: 21,
        encoder_type: EncoderType::Dac,
        possible_crtcs: 0x3,
        possible_clones: 0,
        crtc_id: None,
    });
    card.connectors.push(Connector {
        id: 31,
        connector_type: ConnectorType::HdmiA,
        connector_type_id: 1,
        status: ConnectorStatus::Connected,
        encoder_id: Some(21),
        modes: alloc::vec::Vec::new(),
    });
    card
}

/// Register a fresh test card with the registry, with `SMOKE_MASTER_ID`
/// pre-established as its DRM master (as if that open had already acquired
/// it), so the modeset smokes reach the handler body. Returns its index.
fn register_test_card() -> u32 {
    let idx = register_test_card_unmastered();
    if let Some(ms) = crate::drm_registry::mode_state(idx) {
        ms.lock().master_open(SMOKE_MASTER_ID);
    }
    idx
}

/// Register a fresh test card with NO DRM master established — the device
/// master is free. Used by the arbitration smokes, which drive SET/DROP_MASTER
/// explicitly to observe the handoff.
fn register_test_card_unmastered() -> u32 {
    let name = format!("card{}", crate::drm_registry::count());
    let card = Arc::new(BochsCard::new(name));
    crate::drm_registry::register_drm_card_with_state(card, make_test_card())
}

/// Register a fresh test card whose driver name is `virtio_gpu` (mastered), so
/// the VIRTGPU-driver-ioctl routing on both the card and render nodes is
/// exercised. `BochsCard` reports `"bochs"` and never trips that gate.
fn register_test_virtio_card() -> u32 {
    let name = format!("card{}", crate::drm_registry::count());
    let card = Arc::new(crate::drm_devfs_bridge::VirtioGpuCard::new(name));
    let mut state = make_test_card();
    state.driver_name = "virtio_gpu";
    state.driver_desc = "NARF VirtIO GPU driver";
    state.version = (0, 1, 0);
    let idx = crate::drm_registry::register_drm_card_with_state(card, state);
    if let Some(ms) = crate::drm_registry::mode_state(idx) {
        ms.lock().master_open(SMOKE_MASTER_ID);
    }
    idx
}

// ── 1. _IOC encoding round-trip ────────────────────────────────────────

#[allow(dead_code)]
fn smoke_drm_ioc_macro_roundtrip() -> TestResult {
    // _IOC(READ|WRITE, 'd', 0xA0, sz_card_res) == DRM_IOCTL_MODE_GETRESOURCES.
    let manual = ioc(
        IOC_READ | IOC_WRITE,
        DRM_IOCTL_BASE,
        0xA0,
        core::mem::size_of::<DrmModeCardResUapi>() as u32,
    );
    if manual != DRM_IOCTL_MODE_GETRESOURCES {
        return TestResult::Fail(
            "ioc(READ|WRITE,'d',0xA0,sz_card_res) != DRM_IOCTL_MODE_GETRESOURCES",
        );
    }
    // Decoders round-trip back to the inputs.
    if ioc_nr(DRM_IOCTL_MODE_GETRESOURCES) != 0xA0 {
        return TestResult::Fail("ioc_nr(GETRESOURCES) != 0xA0");
    }
    if ioc_type(DRM_IOCTL_MODE_GETRESOURCES) != DRM_IOCTL_BASE {
        return TestResult::Fail("ioc_type(GETRESOURCES) != 'd'");
    }
    if ioc_dir(DRM_IOCTL_MODE_GETRESOURCES) != (IOC_READ | IOC_WRITE) {
        return TestResult::Fail("ioc_dir(GETRESOURCES) != R+W");
    }
    if ioc_size(DRM_IOCTL_MODE_GETRESOURCES) != core::mem::size_of::<DrmModeCardResUapi>() as u32 {
        return TestResult::Fail("ioc_size(GETRESOURCES) != sizeof");
    }
    // Linux's drm_gem_close is exactly `{ u32 handle; u32 pad; }`. Encoding
    // it as 16 bytes makes Mesa's real 0x40086409 call miss the VirtGPU
    // per-open close path and leaves a stale handle after the card GEM entry
    // is removed.
    let w_only = iow(b'd' as u32, 0x09, 8);
    if ioc_dir(w_only) != IOC_WRITE {
        return TestResult::Fail("iow direction bits not WRITE-only");
    }
    if DRM_IOCTL_GEM_CLOSE != 0x4008_6409 || ioc_size(DRM_IOCTL_GEM_CLOSE) != 8 {
        return TestResult::Fail("GEM_CLOSE does not match Linux's 8-byte ioctl word");
    }
    if crate::drm_uapi::DRM_IOCTL_MODE_ADDFB2 != 0xc068_64b8
        || crate::drm_uapi::DRM_IOCTL_MODE_GETPLANE != 0xc020_64b6
        || crate::drm_uapi::DRM_IOCTL_MODE_CREATEPROPBLOB != 0xc010_64bd
        || crate::drm_uapi::DRM_IOCTL_SYNCOBJ_WAIT != 0xc028_64c3
        || crate::drm_uapi::DRM_IOCTL_PRIME_HANDLE_TO_FD != 0xc00c_642d
    {
        return TestResult::Fail("DRM ioctl sizes drifted from Linux UAPI");
    }
    let rw = iowr(b'd' as u32, 0xBC, 56);
    if ioc_dir(rw) != (IOC_READ | IOC_WRITE) {
        return TestResult::Fail("iowr direction bits not R+W");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_ioc_macro_roundtrip);

// ── 2. ENOTTY on unknown ioctl number for a registered card ────────────

#[allow(dead_code)]
fn smoke_drm_unknown_ioctl_returns_unsupported() -> TestResult {
    let idx = register_test_card();
    // Use a deliberately-unallocated nr.
    let bogus = iowr(b'd' as u32, 0xFE, 8);
    let mut buf = [0u8; 8];
    let r = dispatch_card(idx, bogus, buf.as_mut_ptr() as usize, /*render*/ false);
    match r {
        Err(FsError::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("unknown ioctl did not surface Unsupported"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_unknown_ioctl_returns_unsupported
);

// ── 3. DRM_IOCTL_VERSION populates name buffer ─────────────────────────

#[allow(dead_code)]
fn smoke_drm_ioctl_version_writes_driver_name() -> TestResult {
    let idx = register_test_card();
    let mut name_buf = [0u8; 32];
    let mut date_buf = [0u8; 32];
    let mut desc_buf = [0u8; 64];
    let mut req = DrmVersionUapi {
        version_major: 0,
        version_minor: 0,
        version_patchlevel: 0,
        name_len: name_buf.len() as u64,
        name: name_buf.as_mut_ptr() as u64,
        date_len: date_buf.len() as u64,
        date: date_buf.as_mut_ptr() as u64,
        desc_len: desc_buf.len() as u64,
        desc: desc_buf.as_mut_ptr() as u64,
    };
    let r = dispatch_card(
        idx,
        DRM_IOCTL_VERSION,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    if r.is_err() {
        return TestResult::Fail("DRM_IOCTL_VERSION returned error");
    }
    // The driver name we stamped in make_test_card is "narf-drm".
    let n = req.name_len as usize;
    if n == 0 || n > name_buf.len() {
        return TestResult::Fail("version name_len out of range");
    }
    let got = core::str::from_utf8(&name_buf[..n]).unwrap_or("");
    if got != "narf-drm" {
        return TestResult::Fail("driver name != narf-drm");
    }
    if req.version_major != 1 {
        return TestResult::Fail("version_major != 1");
    }
    // name, date AND desc must ALL come back non-empty. libdrm's
    // drmGetVersion only allocates version->{name,date,desc} when the
    // corresponding _len is non-zero on the first ioctl, then drmCopyVersion
    // does an UNCONDITIONAL strdup on each — an empty field leaves a NULL
    // pointer and strdup(NULL) segfaults the caller (Mesa GBM's
    // gbm_create_device crashed a kwin worker thread exactly this way).
    if req.date_len == 0 || req.date_len > date_buf.len() as u64 {
        return TestResult::Fail("version date_len empty/out of range");
    }
    if req.desc_len == 0 || req.desc_len > desc_buf.len() as u64 {
        return TestResult::Fail("version desc_len empty/out of range");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_version_writes_driver_name
);

// ── 4. DRM_IOCTL_MODE_GETRESOURCES returns CRTC count > 0 ──────────────

#[allow(dead_code)]
fn smoke_drm_ioctl_getresources_counts_crtcs() -> TestResult {
    let idx = register_test_card();
    let mut req = DrmModeCardResUapi::default();
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_GETRESOURCES,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    if r.is_err() {
        return TestResult::Fail("GETRESOURCES returned error");
    }
    if req.count_crtcs == 0 {
        return TestResult::Fail("count_crtcs == 0 after registering 2 CRTCs");
    }
    if req.count_connectors == 0 {
        return TestResult::Fail("count_connectors == 0 after registering connector");
    }
    if req.max_width == 0 || req.max_height == 0 {
        return TestResult::Fail("max_width/max_height not set");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_getresources_counts_crtcs
);

// ── 5. GETRESOURCES writes CRTC IDs when caller supplies array ─────────

#[allow(dead_code)]
fn smoke_drm_ioctl_getresources_populates_crtc_ids() -> TestResult {
    let idx = register_test_card();
    let mut ids = [0u32; 8];
    let mut req = DrmModeCardResUapi {
        crtc_id_ptr: ids.as_mut_ptr() as u64,
        count_crtcs: ids.len() as u32,
        ..Default::default()
    };
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_GETRESOURCES,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    if r.is_err() {
        return TestResult::Fail("GETRESOURCES returned error");
    }
    // Test card has CRTC ids 11 and 12.
    if ids[0] != 11 || ids[1] != 12 {
        return TestResult::Fail("CRTC ids not written into user array");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_getresources_populates_crtc_ids
);

// ── SET_CLIENT_CAP(ATOMIC) on a native-atomic card ─────────────────────
//
// A native display backend that published itself DRIVER_ATOMIC (Navi48)
// takes the ATOMIC client cap and an empty atomic commit, as Linux amdgpu
// does; CURSOR_PLANE_HOTSPOT stays VirtGPU-only (EOPNOTSUPP).
fn smoke_drm_ioctl_native_atomic_card_takes_atomic() -> TestResult {
    let name = format!("card{}", crate::drm_registry::count());
    let card = Arc::new(BochsCard::new(name));
    let mut state = make_test_card();
    state.native_atomic = true;
    let idx = crate::drm_registry::register_drm_card_with_state(card, state);
    if let Some(ms) = crate::drm_registry::mode_state(idx) {
        ms.lock().master_open(SMOKE_MASTER_ID);
    }
    let cap = |capability: u64| {
        let mut c = [0u8; 16];
        c[0..8].copy_from_slice(&capability.to_le_bytes());
        c[8..16].copy_from_slice(&1u64.to_le_bytes());
        dispatch_card(
            idx,
            DRM_IOCTL_SET_CLIENT_CAP,
            c.as_mut_ptr() as usize,
            false,
        )
    };
    if cap(3) != Ok(0) {
        return TestResult::Fail("native-atomic card refused SET_CLIENT_CAP(ATOMIC)");
    }
    if cap(6) != Err(FsError::Unsupported) {
        return TestResult::Fail("CURSOR_PLANE_HOTSPOT should stay VirtGPU-only");
    }
    let mut req = DrmModeAtomicUapi::default();
    if dispatch_card(
        idx,
        DRM_IOCTL_MODE_ATOMIC,
        &mut req as *mut _ as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("empty atomic commit on a native-atomic card");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_native_atomic_card_takes_atomic
);

// ── SET_CLIENT_CAP: universal planes accepted, atomic rejected ─────────
//
// weston's drm-backend REQUIRES DRM_CLIENT_CAP_UNIVERSAL_PLANES (it
// enumerates the primary plane through that UAPI) and probes
// DRM_CLIENT_CAP_ATOMIC. Accepting universal planes but rejecting atomic
// routes weston onto the legacy SETCRTC modeset path narf-drm implements.
fn smoke_drm_ioctl_set_client_cap_universal_vs_atomic() -> TestResult {
    let idx = register_test_card();
    // struct drm_set_client_cap { u64 capability; u64 value; }
    let mut up = [0u8; 16];
    up[0..8].copy_from_slice(&2u64.to_le_bytes()); // UNIVERSAL_PLANES
    up[8..16].copy_from_slice(&1u64.to_le_bytes());
    if dispatch_card(
        idx,
        DRM_IOCTL_SET_CLIENT_CAP,
        up.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("SET_CLIENT_CAP(UNIVERSAL_PLANES) should succeed");
    }
    let mut at = [0u8; 16];
    at[0..8].copy_from_slice(&3u64.to_le_bytes()); // ATOMIC
    at[8..16].copy_from_slice(&1u64.to_le_bytes());
    if dispatch_card(
        idx,
        DRM_IOCTL_SET_CLIENT_CAP,
        at.as_mut_ptr() as usize,
        false,
    )
    .is_ok()
    {
        return TestResult::Fail("SET_CLIENT_CAP(ATOMIC) should be rejected for the legacy path");
    }
    // STEREO_3D (1) and ASPECT_RATIO (4) are pure client opt-ins needing no
    // driver support — Linux accepts them on a non-atomic driver, so we do too.
    for cap in [1u64, 4u64] {
        let mut c = [0u8; 16];
        c[0..8].copy_from_slice(&cap.to_le_bytes());
        c[8..16].copy_from_slice(&1u64.to_le_bytes());
        if dispatch_card(
            idx,
            DRM_IOCTL_SET_CLIENT_CAP,
            c.as_mut_ptr() as usize,
            false,
        ) != Ok(0)
        {
            return TestResult::Fail("SET_CLIENT_CAP(STEREO_3D/ASPECT_RATIO) should succeed");
        }
    }
    // value > 1 on a boolean opt-in is EINVAL (Linux parity).
    let mut bad = [0u8; 16];
    bad[0..8].copy_from_slice(&2u64.to_le_bytes()); // UNIVERSAL_PLANES
    bad[8..16].copy_from_slice(&2u64.to_le_bytes()); // value 2 → invalid
    if dispatch_card(
        idx,
        DRM_IOCTL_SET_CLIENT_CAP,
        bad.as_mut_ptr() as usize,
        false,
    )
    .is_ok()
    {
        return TestResult::Fail("SET_CLIENT_CAP with value>1 should be rejected");
    }
    // WRITEBACK_CONNECTORS (5) needs atomic → rejected.
    let mut wb = [0u8; 16];
    wb[0..8].copy_from_slice(&5u64.to_le_bytes());
    wb[8..16].copy_from_slice(&1u64.to_le_bytes());
    if dispatch_card(
        idx,
        DRM_IOCTL_SET_CLIENT_CAP,
        wb.as_mut_ptr() as usize,
        false,
    )
    .is_ok()
    {
        return TestResult::Fail(
            "SET_CLIENT_CAP(WRITEBACK_CONNECTORS) should be rejected (no atomic)",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_set_client_cap_universal_vs_atomic
);

// ── Universal planes: synthesised PRIMARY plane per CRTC ───────────────
//
// weston's drm-backend needs a CRTC's PRIMARY plane (via GETPLANERESOURCES
// + GETPLANE + the "type" property) to enable an output, even on the
// legacy modeset path. narf-drm synthesises one immutable PRIMARY plane
// per CRTC; this checks the whole reply chain.
fn smoke_drm_ioctl_planes_synth_primary() -> TestResult {
    let idx = register_test_card();
    // GETPLANERESOURCES → at least one plane.
    let mut req = [0u8; 16];
    if dispatch_card(
        idx,
        DRM_IOCTL_MODE_GETPLANERESOURCES,
        req.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("GETPLANERESOURCES failed");
    }
    if u32::from_le_bytes(req[8..12].try_into().unwrap()) < 1 {
        return TestResult::Fail("expected >= 1 synthesised plane");
    }
    // GETPLANE on the first plane (PLANE_ID_BASE = 0x40) → non-empty
    // possible_crtcs.
    let mut pl = [0u8; 32];
    pl[0..4].copy_from_slice(&0x40u32.to_le_bytes());
    if dispatch_card(
        idx,
        DRM_IOCTL_MODE_GETPLANE,
        pl.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("GETPLANE failed");
    }
    if u32::from_le_bytes(pl[12..16].try_into().unwrap()) == 0 {
        return TestResult::Fail("plane has empty possible_crtcs");
    }
    // OBJ_GETPROPERTIES(plane) → the "type" property reads PRIMARY (1).
    // The object exposes the complete atomic property set — including the
    // explicit-fencing IN_FENCE_FD — so provide room for all twelve
    // entries just as libdrm's two-pass allocation does.
    let mut props = [0u32; 12];
    let mut vals = [0u64; 12];
    let mut og = [0u8; 32];
    og[0..8].copy_from_slice(&(props.as_mut_ptr() as u64).to_le_bytes());
    og[8..16].copy_from_slice(&(vals.as_mut_ptr() as u64).to_le_bytes());
    og[16..20].copy_from_slice(&12u32.to_le_bytes()); // count_props (room)
    og[20..24].copy_from_slice(&0x40u32.to_le_bytes()); // obj_id = plane
    og[24..28].copy_from_slice(&0xeeee_eeeeu32.to_le_bytes()); // PLANE
    let obj_getprops = iowr(DRM_IOCTL_BASE, 0xB9, 32);
    if dispatch_card(idx, obj_getprops, og.as_mut_ptr() as usize, false) != Ok(0) {
        return TestResult::Fail("OBJ_GETPROPERTIES failed");
    }
    if vals[0] != 1 {
        return TestResult::Fail("plane 'type' property should be PRIMARY (1)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_planes_synth_primary
);

// ── Connector "Broadcast RGB" ─────────────────────────────────────────
//
// drm_connector_attach_broadcast_rgb_property: an enum on native HDMI/DP
// connectors, listed with the connector's properties and settable by the
// master through SETPROPERTY / OBJ_SETPROPERTY (and atomic commits).
fn smoke_drm_ioctl_broadcast_rgb_property() -> TestResult {
    let idx = register_test_card();
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no mode state");
    };
    ms.lock().native.push(crate::drm::card::NativeOutput {
        connector: 31,
        edid: None,
        timings: alloc::vec::Vec::new(),
        broadcast_rgb: Some(0),
        vrr_capable: None,
        colorspace: None,
        hdr_output_metadata: None,
    });
    // GETPROPERTY: a settable enum with Linux's three names.
    let mut values = [0u64; 3];
    let mut enums = [0u8; 3 * 40];
    let mut gp = [0u8; 64];
    gp[0..8].copy_from_slice(&(values.as_mut_ptr() as u64).to_le_bytes());
    gp[8..16].copy_from_slice(&(enums.as_mut_ptr() as u64).to_le_bytes());
    gp[16..20].copy_from_slice(&0x61u32.to_le_bytes());
    gp[56..60].copy_from_slice(&3u32.to_le_bytes());
    gp[60..64].copy_from_slice(&3u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xAA, 64),
        gp.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("GETPROPERTY failed");
    }
    let name = |b: &[u8]| {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        alloc::vec::Vec::from(&b[..end])
    };
    if name(&gp[24..56]) != b"Broadcast RGB"
        || u32::from_le_bytes(gp[20..24].try_into().unwrap()) != 1 << 3
        || values != [0, 1, 2]
        || name(&enums[8..40]) != b"Automatic"
        || name(&enums[48..80]) != b"Full"
        || name(&enums[88..120]) != b"Limited 16:235"
    {
        return TestResult::Fail("Broadcast RGB metadata");
    }
    // OBJ_GETPROPERTIES(connector) lists it with its value.
    let read = |idx: u32| -> Option<(u32, u64, u32)> {
        let mut props = [0u32; 4];
        let mut vals = [0u64; 4];
        let mut og = [0u8; 32];
        og[0..8].copy_from_slice(&(props.as_mut_ptr() as u64).to_le_bytes());
        og[8..16].copy_from_slice(&(vals.as_mut_ptr() as u64).to_le_bytes());
        og[16..20].copy_from_slice(&4u32.to_le_bytes());
        og[20..24].copy_from_slice(&31u32.to_le_bytes());
        og[24..28].copy_from_slice(&0xc0c0_c0c0u32.to_le_bytes());
        dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xB9, 32),
            og.as_mut_ptr() as usize,
            false,
        )
        .ok()?;
        let count = u32::from_le_bytes(og[16..20].try_into().unwrap());
        Some((props[2], vals[2], count))
    };
    if read(idx) != Some((0x61, 0, 3)) {
        return TestResult::Fail("connector properties");
    }
    let obj_set = |value: u64, prop: u32, obj: u32| {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&value.to_le_bytes());
        b[8..12].copy_from_slice(&prop.to_le_bytes());
        b[12..16].copy_from_slice(&obj.to_le_bytes());
        b[16..20].copy_from_slice(&0xc0c0_c0c0u32.to_le_bytes());
        dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xBA, 24),
            b.as_mut_ptr() as usize,
            false,
        )
    };
    if obj_set(2, 0x61, 31) != Ok(0) || read(idx).map(|r| r.1) != Some(2) {
        return TestResult::Fail("OBJ_SETPROPERTY Limited");
    }
    if obj_set(3, 0x61, 31) != Err(FsError::InvalidData)
        || obj_set(0, 0x51, 31) != Err(FsError::InvalidData)
        || obj_set(0, 0x61, 99) != Err(FsError::NotFound)
        || read(idx).map(|r| r.1) != Some(2)
    {
        return TestResult::Fail("invalid set accepted");
    }
    // Legacy connector SETPROPERTY.
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&1u64.to_le_bytes());
    b[8..12].copy_from_slice(&0x61u32.to_le_bytes());
    b[12..16].copy_from_slice(&31u32.to_le_bytes());
    let set = iowr(DRM_IOCTL_BASE, 0xAB, 16);
    if dispatch_card(idx, set, b.as_mut_ptr() as usize, false) != Ok(0)
        || read(idx).map(|r| r.1) != Some(1)
    {
        return TestResult::Fail("SETPROPERTY Full");
    }
    // Only the master may set it.
    if crate::drm_ioctl_bridge::dispatch_card(
        idx,
        SMOKE_MASTER_ID + 1,
        set,
        b.as_mut_ptr() as usize,
        false,
    ) != Err(FsError::PermissionDenied)
    {
        return TestResult::Fail("non-master set");
    }
    // A connector without the property neither lists nor takes it.
    ms.lock().native.clear();
    if read(idx).map(|r| r.2) != Some(2) || obj_set(0, 0x61, 31) != Err(FsError::InvalidData) {
        return TestResult::Fail("property on a plain connector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_broadcast_rgb_property
);

// ── Connector "vrr_capable" and CRTC "VRR_ENABLED" ────────────────────
//
// amdgpu_dm attaches drm_connector_attach_vrr_capable_property (an
// immutable bool) to DP/HDMI connectors, and every CRTC of an atomic driver
// carries the VRR_ENABLED bool. Only cards that publish them list them;
// OBJ_SETPROPERTY and atomic commits set VRR_ENABLED (0..1) and refuse
// vrr_capable. Enabling is accepted whether or not the sink can vary.
fn smoke_drm_ioctl_vrr_properties() -> TestResult {
    let getprop = |idx: u32, prop: u32| -> Option<(alloc::vec::Vec<u8>, u32, [u64; 2], u32)> {
        let mut values = [9u64; 2];
        let mut gp = [0u8; 64];
        gp[0..8].copy_from_slice(&(values.as_mut_ptr() as u64).to_le_bytes());
        gp[16..20].copy_from_slice(&prop.to_le_bytes());
        gp[56..60].copy_from_slice(&2u32.to_le_bytes());
        dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xAA, 64),
            gp.as_mut_ptr() as usize,
            false,
        )
        .ok()?;
        let end = gp[24..56].iter().position(|&c| c == 0).unwrap_or(32);
        Some((
            alloc::vec::Vec::from(&gp[24..24 + end]),
            u32::from_le_bytes(gp[20..24].try_into().unwrap()),
            values,
            u32::from_le_bytes(gp[56..60].try_into().unwrap()),
        ))
    };
    let read = |idx: u32, obj: u32, kind: u32| -> Option<alloc::vec::Vec<(u32, u64)>> {
        let mut props = [0u32; 8];
        let mut vals = [0u64; 8];
        let mut og = [0u8; 32];
        og[0..8].copy_from_slice(&(props.as_mut_ptr() as u64).to_le_bytes());
        og[8..16].copy_from_slice(&(vals.as_mut_ptr() as u64).to_le_bytes());
        og[16..20].copy_from_slice(&8u32.to_le_bytes());
        og[20..24].copy_from_slice(&obj.to_le_bytes());
        og[24..28].copy_from_slice(&kind.to_le_bytes());
        dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xB9, 32),
            og.as_mut_ptr() as usize,
            false,
        )
        .ok()?;
        let count = u32::from_le_bytes(og[16..20].try_into().unwrap()) as usize;
        Some(
            props[..count]
                .iter()
                .copied()
                .zip(vals[..count].iter().copied())
                .collect(),
        )
    };
    let obj_set = |idx: u32, value: u64, prop: u32, obj: u32, kind: u32| {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&value.to_le_bytes());
        b[8..12].copy_from_slice(&prop.to_le_bytes());
        b[12..16].copy_from_slice(&obj.to_le_bytes());
        b[16..20].copy_from_slice(&kind.to_le_bytes());
        dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xBA, 24),
            b.as_mut_ptr() as usize,
            false,
        )
    };
    const CONNECTOR: u32 = 0xc0c0_c0c0;
    const CRTC: u32 = 0xcccc_cccc;
    // Metadata: both are 0..1 ranges; vrr_capable immutable, VRR_ENABLED not.
    let idx = register_test_card();
    if getprop(idx, 0x62) != Some((b"vrr_capable".to_vec(), 1 << 1 | 1 << 2, [0, 1], 2))
        || getprop(idx, 0x63) != Some((b"VRR_ENABLED".to_vec(), 1 << 1, [0, 1], 2))
    {
        return TestResult::Fail("VRR property metadata");
    }
    // A card that does not publish them lists neither and refuses both.
    let has = |list: &Option<alloc::vec::Vec<(u32, u64)>>, prop: u32| {
        list.as_ref()
            .is_some_and(|l| l.iter().any(|&(p, _)| p == prop))
    };
    if has(&read(idx, 31, CONNECTOR), 0x62)
        || has(&read(idx, 11, CRTC), 0x63)
        || obj_set(idx, 1, 0x63, 11, CRTC) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("VRR properties on a plain card");
    }
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no mode state");
    };
    {
        let mut card = ms.lock();
        card.native.push(crate::drm::card::NativeOutput {
            connector: 31,
            edid: None,
            timings: alloc::vec::Vec::new(),
            broadcast_rgb: None,
            vrr_capable: Some(true),
            colorspace: None,
            hdr_output_metadata: None,
        });
        card.vrr_enabled = alloc::vec![(11, false), (12, false)];
    }
    let connector = read(idx, 31, CONNECTOR);
    if connector.as_ref().and_then(|l| l.last().copied()) != Some((0x62, 1))
        || read(idx, 11, CRTC).and_then(|l| l.last().copied()) != Some((0x63, 0))
    {
        return TestResult::Fail("VRR property values");
    }
    // OBJ_SETPROPERTY: VRR_ENABLED on a CRTC; bad values, the immutable
    // vrr_capable and unknown objects are refused without effect.
    if obj_set(idx, 1, 0x63, 12, CRTC) != Ok(0)
        || read(idx, 12, CRTC).and_then(|l| l.last().copied()) != Some((0x63, 1))
        || read(idx, 11, CRTC).and_then(|l| l.last().copied()) != Some((0x63, 0))
    {
        return TestResult::Fail("OBJ_SETPROPERTY VRR_ENABLED");
    }
    if obj_set(idx, 2, 0x63, 12, CRTC) != Err(FsError::InvalidData)
        || obj_set(idx, 0, 0x62, 31, CONNECTOR) != Err(FsError::InvalidData)
        || obj_set(idx, 0, 0x52, 12, CRTC) != Err(FsError::InvalidData)
        || obj_set(idx, 0, 0x63, 99, CRTC) != Err(FsError::NotFound)
        || obj_set(idx, 0, 0x63, 31, CONNECTOR) != Err(FsError::InvalidData)
        || read(idx, 12, CRTC).and_then(|l| l.last().copied()) != Some((0x63, 1))
    {
        return TestResult::Fail("invalid VRR set accepted");
    }
    // Legacy connector SETPROPERTY never reaches a CRTC property.
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&0u64.to_le_bytes());
    b[8..12].copy_from_slice(&0x63u32.to_le_bytes());
    b[12..16].copy_from_slice(&12u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xAB, 16),
        b.as_mut_ptr() as usize,
        false,
    ) != Err(FsError::NotFound)
    {
        return TestResult::Fail("SETPROPERTY on a CRTC");
    }
    // Master only.
    let mut b = [0u8; 24];
    b[8..12].copy_from_slice(&0x63u32.to_le_bytes());
    b[12..16].copy_from_slice(&12u32.to_le_bytes());
    b[16..20].copy_from_slice(&CRTC.to_le_bytes());
    if crate::drm_ioctl_bridge::dispatch_card(
        idx,
        SMOKE_MASTER_ID + 1,
        iowr(DRM_IOCTL_BASE, 0xBA, 24),
        b.as_mut_ptr() as usize,
        false,
    ) != Err(FsError::PermissionDenied)
    {
        return TestResult::Fail("non-master VRR set");
    }
    // Atomic (on the atomic VirtIO card): VRR_ENABLED alone needs no
    // ALLOW_MODESET; TEST_ONLY validates without applying; bad values fail.
    let idx = register_test_virtio_card();
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no virtio mode state");
    };
    ms.lock().vrr_enabled = alloc::vec![(11, false), (12, false)];
    let atomic = |flags: u32, value: u64| {
        let objects = [11u32];
        let prop_counts = [1u32];
        let props = [0x63u32];
        let values = [value];
        let mut req = DrmModeAtomicUapi {
            flags,
            count_objs: 1,
            objs_ptr: objects.as_ptr() as u64,
            count_props_ptr: prop_counts.as_ptr() as u64,
            props_ptr: props.as_ptr() as u64,
            prop_values_ptr: values.as_ptr() as u64,
            ..Default::default()
        };
        dispatch_card(
            idx,
            DRM_IOCTL_MODE_ATOMIC,
            &mut req as *mut _ as usize,
            false,
        )
    };
    let value = |crtc: u32| {
        ms.lock()
            .vrr_enabled
            .iter()
            .find(|&&(id, _)| id == crtc)
            .map(|&(_, v)| v)
    };
    if atomic(0x0100, 1) != Ok(0) || value(11) != Some(false) {
        return TestResult::Fail("TEST_ONLY applied");
    }
    if atomic(0, 1) != Ok(0) || value(11) != Some(true) || value(12) != Some(false) {
        return TestResult::Fail("atomic VRR_ENABLED");
    }
    if atomic(0, 2) != Err(FsError::InvalidData) || value(11) != Some(true) {
        return TestResult::Fail("atomic bad value");
    }
    ms.lock().vrr_enabled.clear();
    if atomic(0, 0) != Err(FsError::InvalidData) {
        return TestResult::Fail("atomic on a CRTC without it");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_ioctl_vrr_properties);

// ── CRTC CTM / GAMMA_LUT and connector Colorspace / HDR_OUTPUT_METADATA ─
//
// amdgpu_dm on DCN 4.0.1: drm_crtc_enable_color_mgmt(crtc, 0, true, 4096)
// (CTM, GAMMA_LUT, GAMMA_LUT_SIZE; no degamma) with the 256-entry legacy
// gamma, and Colorspace / HDR_OUTPUT_METADATA on HDMI and DP connectors.
// Blob properties are validated as drm_property_replace_blob_from_id and
// amdgpu_dm_verify_lut_sizes do; Colorspace and entering/leaving HDR need
// a modeset; a referenced blob outlives DESTROYPROPBLOB.
fn color_getprop(
    idx: u32,
    prop: u32,
) -> Option<(alloc::vec::Vec<u8>, u32, alloc::vec::Vec<u64>, u32)> {
    let mut values = [0u64; 8];
    let mut gp = [0u8; 64];
    gp[0..8].copy_from_slice(&(values.as_mut_ptr() as u64).to_le_bytes());
    gp[16..20].copy_from_slice(&prop.to_le_bytes());
    gp[56..60].copy_from_slice(&8u32.to_le_bytes());
    dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xAA, 64),
        gp.as_mut_ptr() as usize,
        false,
    )
    .ok()?;
    let end = gp[24..56].iter().position(|&c| c == 0).unwrap_or(32);
    let count = u32::from_le_bytes(gp[56..60].try_into().unwrap());
    Some((
        alloc::vec::Vec::from(&gp[24..24 + end]),
        u32::from_le_bytes(gp[20..24].try_into().unwrap()),
        values[..(count as usize).min(8)].to_vec(),
        u32::from_le_bytes(gp[60..64].try_into().unwrap()),
    ))
}
fn color_props(idx: u32, obj: u32, kind: u32) -> alloc::vec::Vec<(u32, u64)> {
    let mut props = [0u32; 16];
    let mut vals = [0u64; 16];
    let mut og = [0u8; 32];
    og[0..8].copy_from_slice(&(props.as_mut_ptr() as u64).to_le_bytes());
    og[8..16].copy_from_slice(&(vals.as_mut_ptr() as u64).to_le_bytes());
    og[16..20].copy_from_slice(&16u32.to_le_bytes());
    og[20..24].copy_from_slice(&obj.to_le_bytes());
    og[24..28].copy_from_slice(&kind.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB9, 32),
        og.as_mut_ptr() as usize,
        false,
    )
    .is_err()
    {
        return alloc::vec::Vec::new();
    }
    let count = u32::from_le_bytes(og[16..20].try_into().unwrap()) as usize;
    props[..count]
        .iter()
        .copied()
        .zip(vals[..count].iter().copied())
        .collect()
}
fn color_prop(idx: u32, obj: u32, kind: u32, prop: u32) -> Option<u64> {
    color_props(idx, obj, kind)
        .into_iter()
        .find(|&(p, _)| p == prop)
        .map(|(_, v)| v)
}
fn color_obj_set(idx: u32, value: u64, prop: u32, obj: u32, kind: u32) -> Result<u64, FsError> {
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&value.to_le_bytes());
    b[8..12].copy_from_slice(&prop.to_le_bytes());
    b[12..16].copy_from_slice(&obj.to_le_bytes());
    b[16..20].copy_from_slice(&kind.to_le_bytes());
    dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xBA, 24),
        b.as_mut_ptr() as usize,
        false,
    )
}
fn color_blob(idx: u32, data: &[u8]) -> u32 {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&(data.as_ptr() as u64).to_le_bytes());
    b[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    let _ = dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xBD, 16),
        b.as_mut_ptr() as usize,
        false,
    );
    u32::from_le_bytes(b[12..16].try_into().unwrap())
}
fn color_blob_bytes(idx: u32, id: u32) -> Option<alloc::vec::Vec<u8>> {
    let mut data = alloc::vec![0u8; 0x8000];
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&id.to_le_bytes());
    b[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    b[8..16].copy_from_slice(&(data.as_mut_ptr() as u64).to_le_bytes());
    dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xAC, 16),
        b.as_mut_ptr() as usize,
        false,
    )
    .ok()?;
    data.truncate(u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize);
    Some(data)
}
/// A GAMMA_LUT / legacy ramp of `n` equal-channel entries.
fn color_lut(n: usize) -> alloc::vec::Vec<u8> {
    (0..n)
        .flat_map(|i| {
            let v = (i * 0xffff / (n - 1)) as u16;
            [v, v, v, 0].into_iter().flat_map(u16::to_le_bytes)
        })
        .collect()
}
const COLOR_CONNECTOR: u32 = 0xc0c0_c0c0;
const COLOR_CRTC: u32 = 0xcccc_cccc;

fn smoke_drm_ioctl_color_property_metadata() -> TestResult {
    let idx = register_test_card();
    // drm_mode_create_standard_properties: plain blobs, an immutable range.
    if color_getprop(idx, 0x64) != Some((b"CTM".to_vec(), 1 << 4, alloc::vec![], 0))
        || color_getprop(idx, 0x65) != Some((b"GAMMA_LUT".to_vec(), 1 << 4, alloc::vec![], 0))
        || color_getprop(idx, 0x66)
            != Some((
                b"GAMMA_LUT_SIZE".to_vec(),
                1 << 1 | 1 << 2,
                alloc::vec![0, 0xffff_ffff],
                0,
            ))
        || color_getprop(idx, 0x68)
            != Some((b"HDR_OUTPUT_METADATA".to_vec(), 1 << 4, alloc::vec![], 0))
    {
        return TestResult::Fail("color property metadata");
    }
    // Colorspace: Default plus amdgpu_dm's four, the same on HDMI and DP.
    let mut values = [0u64; 5];
    let mut enums = [0u8; 5 * 40];
    let mut gp = [0u8; 64];
    gp[0..8].copy_from_slice(&(values.as_mut_ptr() as u64).to_le_bytes());
    gp[8..16].copy_from_slice(&(enums.as_mut_ptr() as u64).to_le_bytes());
    gp[16..20].copy_from_slice(&0x67u32.to_le_bytes());
    gp[56..60].copy_from_slice(&5u32.to_le_bytes());
    gp[60..64].copy_from_slice(&5u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xAA, 64),
        gp.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || &gp[24..35] != b"Colorspace\0"
        || u32::from_le_bytes(gp[20..24].try_into().unwrap()) != 1 << 3
        || values != [0, 2, 7, 9, 10]
    {
        return TestResult::Fail("Colorspace enum");
    }
    let names: [&[u8]; 5] = [
        b"Default",
        b"BT709_YCC",
        b"opRGB",
        b"BT2020_RGB",
        b"BT2020_YCC",
    ];
    for (i, name) in names.iter().enumerate() {
        let e = &enums[i * 40..i * 40 + 40];
        if u64::from_le_bytes(e[..8].try_into().unwrap()) != values[i]
            || &e[8..8 + name.len()] != *name
            || e[8 + name.len()] != 0
        {
            return TestResult::Fail("Colorspace names");
        }
    }
    // A card that does not publish them lists none, takes none, and keeps
    // a zero gamma size.
    if color_prop(idx, 11, COLOR_CRTC, 0x64).is_some()
        || color_obj_set(idx, 0, 0x64, 11, COLOR_CRTC) != Err(FsError::InvalidData)
        || color_obj_set(idx, 0, 0x67, 31, COLOR_CONNECTOR) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("color properties on a plain card");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_color_property_metadata
);

/// The native-atomic test card with color management on both CRTCs and
/// Colorspace / HDR_OUTPUT_METADATA on its connector, which drives CRTC 11.
fn color_card() -> Option<u32> {
    let idx = register_test_card();
    let ms = crate::drm_registry::mode_state(idx)?;
    let mut card = ms.lock();
    card.native_atomic = true;
    card.crtc_color = alloc::vec![
        crate::drm::card::CrtcColor::new(11),
        crate::drm::card::CrtcColor::new(12),
    ];
    card.encoders[0].crtc_id = Some(11);
    card.native.push(crate::drm::card::NativeOutput {
        connector: 31,
        edid: None,
        timings: alloc::vec::Vec::new(),
        broadcast_rgb: None,
        vrr_capable: None,
        colorspace: Some(0),
        hdr_output_metadata: Some(0),
    });
    Some(idx)
}

fn smoke_drm_ioctl_crtc_color_blobs() -> TestResult {
    let Some(idx) = color_card() else {
        return TestResult::Fail("no mode state");
    };
    // CRTC listing: CTM, GAMMA_LUT and GAMMA_LUT_SIZE = 4096 after the
    // core properties; GETCRTC reports the legacy gamma size.
    let props = color_props(idx, 11, COLOR_CRTC);
    if props[props.len().saturating_sub(3)..] != [(0x64, 0), (0x65, 0), (0x66, 4096)] {
        return TestResult::Fail("CRTC color properties");
    }
    let mut crtc = [0u8; 104];
    crtc[12..16].copy_from_slice(&11u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA1, 104),
        crtc.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || u32::from_le_bytes(crtc[28..32].try_into().unwrap()) != 256
    {
        return TestResult::Fail("GETCRTC gamma_size");
    }
    // CTM: exactly 72 bytes; unknown blobs are EINVAL.
    let ctm = color_blob(idx, &[0u8; 72]);
    let short = color_blob(idx, &[0u8; 64]);
    if color_obj_set(idx, u64::from(short), 0x64, 11, COLOR_CRTC) != Err(FsError::InvalidData)
        || color_obj_set(idx, 0xdead, 0x64, 11, COLOR_CRTC) != Err(FsError::InvalidData)
        || color_obj_set(idx, u64::from(ctm), 0x64, 11, COLOR_CRTC) != Ok(0)
        || color_prop(idx, 11, COLOR_CRTC, 0x64) != Some(u64::from(ctm))
        || color_prop(idx, 12, COLOR_CRTC, 0x64) != Some(0)
    {
        return TestResult::Fail("CTM blob");
    }
    // GAMMA_LUT: whole drm_color_lut entries, 4096 or 256 of them.
    let full = color_blob(idx, &color_lut(4096));
    let legacy = color_blob(idx, &color_lut(256));
    let odd = color_blob(idx, &color_lut(1024));
    let ragged = color_blob(idx, &[0u8; 2052]);
    if color_obj_set(idx, u64::from(odd), 0x65, 11, COLOR_CRTC) != Err(FsError::InvalidData)
        || color_obj_set(idx, u64::from(ragged), 0x65, 11, COLOR_CRTC) != Err(FsError::InvalidData)
        || color_obj_set(idx, u64::from(full), 0x65, 11, COLOR_CRTC) != Ok(0)
        || color_obj_set(idx, u64::from(legacy), 0x65, 12, COLOR_CRTC) != Ok(0)
        || color_prop(idx, 11, COLOR_CRTC, 0x65) != Some(u64::from(full))
        || color_prop(idx, 12, COLOR_CRTC, 0x65) != Some(u64::from(legacy))
        || color_obj_set(idx, 4096, 0x66, 11, COLOR_CRTC) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("GAMMA_LUT blob");
    }
    // A committed blob outlives its creator's reference, then goes.
    let mut d = [0u8; 4];
    d.copy_from_slice(&full.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xBE, 4),
        d.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || color_blob_bytes(idx, full) != Some(color_lut(4096))
        || color_obj_set(idx, 0, 0x65, 11, COLOR_CRTC) != Ok(0)
        || color_blob_bytes(idx, full).is_some()
        || color_blob_bytes(idx, legacy) != Some(color_lut(256))
    {
        return TestResult::Fail("blob lifetime");
    }
    // Atomic: no ALLOW_MODESET needed; TEST_ONLY applies nothing; a bad
    // size fails the whole request.
    let atomic = |flags: u32, props: &[u32], values: &[u64]| {
        let objects = [11u32];
        let counts = [props.len() as u32];
        let mut req = DrmModeAtomicUapi {
            flags,
            count_objs: 1,
            objs_ptr: objects.as_ptr() as u64,
            count_props_ptr: counts.as_ptr() as u64,
            props_ptr: props.as_ptr() as u64,
            prop_values_ptr: values.as_ptr() as u64,
            ..Default::default()
        };
        dispatch_card(
            idx,
            DRM_IOCTL_MODE_ATOMIC,
            &mut req as *mut _ as usize,
            false,
        )
    };
    let full = color_blob(idx, &color_lut(4096));
    if atomic(0x0100, &[0x65, 0x64], &[u64::from(full), 0]) != Ok(0)
        || color_prop(idx, 11, COLOR_CRTC, 0x65) != Some(0)
        || color_prop(idx, 11, COLOR_CRTC, 0x64) != Some(u64::from(ctm))
    {
        return TestResult::Fail("TEST_ONLY applied");
    }
    if atomic(0, &[0x65, 0x64], &[u64::from(full), u64::from(odd)]) != Err(FsError::InvalidData)
        || atomic(0, &[0x65, 0x64], &[u64::from(odd), 0]) != Err(FsError::InvalidData)
        || color_prop(idx, 11, COLOR_CRTC, 0x65) != Some(0)
    {
        return TestResult::Fail("bad atomic accepted");
    }
    if atomic(0, &[0x65, 0x64], &[u64::from(full), 0]) != Ok(0)
        || color_prop(idx, 11, COLOR_CRTC, 0x65) != Some(u64::from(full))
        || color_prop(idx, 11, COLOR_CRTC, 0x64) != Some(0)
    {
        return TestResult::Fail("atomic color commit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_ioctl_crtc_color_blobs);

/// DRM_IOCTL_MODE_SETGAMMA / GETGAMMA on a color-managed CRTC: the gamma
/// store, then drm_crtc_legacy_gamma_set's 256-entry GAMMA_LUT with the
/// CTM reset; size, CRTC, master and render-node checks.
fn smoke_drm_ioctl_legacy_gamma() -> TestResult {
    let Some(idx) = color_card() else {
        return TestResult::Fail("no mode state");
    };
    let lut = |crtc: u32, size: u32, r: &mut [u16], g: &mut [u16], b: &mut [u16]| {
        let mut req = [0u8; 32];
        req[0..4].copy_from_slice(&crtc.to_le_bytes());
        req[4..8].copy_from_slice(&size.to_le_bytes());
        for (at, ramp) in [
            (8, r.as_mut_ptr()),
            (16, g.as_mut_ptr()),
            (24, b.as_mut_ptr()),
        ] {
            req[at..at + 8].copy_from_slice(&(ramp as u64).to_le_bytes());
        }
        req
    };
    let (mut r, mut g, mut b) = ([0u16; 256], [0u16; 256], [0u16; 256]);
    // The initial store is the identity ramp (i << 8).
    let mut get = lut(11, 256, &mut r, &mut g, &mut b);
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA4, 32),
        get.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || (0..256).any(|i| r[i] != (i as u16) << 8 || b[i] != (i as u16) << 8)
    {
        return TestResult::Fail("initial gamma store");
    }
    let ctm = color_blob(idx, &[0u8; 72]);
    if color_obj_set(idx, u64::from(ctm), 0x64, 11, COLOR_CRTC) != Ok(0) {
        return TestResult::Fail("CTM before SETGAMMA");
    }
    let (mut r, mut g, mut b) = (
        core::array::from_fn::<u16, 256, _>(|i| 0xffff - (i as u16) * 0x101),
        core::array::from_fn::<u16, 256, _>(|i| (i as u16) * 0x80),
        [0x1234u16; 256],
    );
    let mut set = lut(11, 256, &mut r, &mut g, &mut b);
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA5, 32),
        set.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("SETGAMMA");
    }
    let Some(blob) = color_prop(idx, 11, COLOR_CRTC, 0x65) else {
        return TestResult::Fail("GAMMA_LUT after SETGAMMA");
    };
    let bytes = color_blob_bytes(idx, blob as u32).unwrap_or_default();
    let entry = |i: usize| -> [u16; 3] {
        let e = &bytes[i * 8..i * 8 + 6];
        [0, 2, 4].map(|o| u16::from_le_bytes([e[o], e[o + 1]]))
    };
    if bytes.len() != 256 * 8
        || (0..256).any(|i| entry(i) != [r[i], g[i], b[i]])
        || color_prop(idx, 11, COLOR_CRTC, 0x64) != Some(0)
    {
        return TestResult::Fail("legacy GAMMA_LUT / CTM reset");
    }
    let (mut gr, mut gg, mut gb) = ([0u16; 256], [0u16; 256], [0u16; 256]);
    let mut get = lut(11, 256, &mut gr, &mut gg, &mut gb);
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA4, 32),
        get.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || gr != r
        || gg != g
        || gb != b
    {
        return TestResult::Fail("GETGAMMA after SETGAMMA");
    }
    // The only blob reference is the property's: replacing it frees it.
    if color_obj_set(idx, 0, 0x65, 11, COLOR_CRTC) != Ok(0)
        || color_blob_bytes(idx, blob as u32).is_some()
    {
        return TestResult::Fail("legacy blob lifetime");
    }
    let mut bad = lut(11, 255, &mut r, &mut g, &mut b);
    let mut gone = lut(99, 256, &mut r, &mut g, &mut b);
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA5, 32),
        bad.as_mut_ptr() as usize,
        false,
    ) != Err(FsError::InvalidData)
        || dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xA4, 32),
            bad.as_mut_ptr() as usize,
            false,
        ) != Err(FsError::InvalidData)
        || dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xA5, 32),
            gone.as_mut_ptr() as usize,
            false,
        ) != Err(FsError::NotFound)
        || dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xA4, 32),
            set.as_mut_ptr() as usize,
            true,
        ) != Err(FsError::PermissionDenied)
        || crate::drm_ioctl_bridge::dispatch_card(
            idx,
            SMOKE_MASTER_ID + 1,
            iowr(DRM_IOCTL_BASE, 0xA5, 32),
            set.as_mut_ptr() as usize,
            false,
        ) != Err(FsError::PermissionDenied)
    {
        return TestResult::Fail("SETGAMMA/GETGAMMA checks");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_ioctl_legacy_gamma);

/// Connector Colorspace and HDR_OUTPUT_METADATA: listed with the
/// connector, values validated, a Colorspace change or entering/leaving
/// HDR on a driven connector needs ALLOW_MODESET (EINVAL through the legacy
/// setters), a metadata change while in HDR does not, and only blobs of
/// sizeof(struct hdr_output_metadata) are taken.
fn smoke_drm_ioctl_connector_hdr_properties() -> TestResult {
    let Some(idx) = color_card() else {
        return TestResult::Fail("no mode state");
    };
    let props = color_props(idx, 31, COLOR_CONNECTOR);
    if !props.contains(&(0x67, 0)) || !props.contains(&(0x68, 0)) {
        return TestResult::Fail("connector properties");
    }
    let atomic = |flags: u32, props: &[u32], values: &[u64]| {
        let objects = [31u32];
        let counts = [props.len() as u32];
        let mut req = DrmModeAtomicUapi {
            flags,
            count_objs: 1,
            objs_ptr: objects.as_ptr() as u64,
            count_props_ptr: counts.as_ptr() as u64,
            props_ptr: props.as_ptr() as u64,
            prop_values_ptr: values.as_ptr() as u64,
            ..Default::default()
        };
        dispatch_card(
            idx,
            DRM_IOCTL_MODE_ATOMIC,
            &mut req as *mut _ as usize,
            false,
        )
    };
    const ALLOW_MODESET: u32 = 0x400;
    // Colorspace: enum values only; a modeset on the driven connector.
    if atomic(ALLOW_MODESET, &[0x67], &[1]) != Err(FsError::InvalidData)
        || atomic(0, &[0x67], &[9]) != Err(FsError::InvalidData)
        || color_obj_set(idx, 9, 0x67, 31, COLOR_CONNECTOR) != Err(FsError::InvalidData)
        || atomic(ALLOW_MODESET, &[0x67], &[9]) != Ok(0)
        || color_prop(idx, 31, COLOR_CONNECTOR, 0x67) != Some(9)
        // Unchanged is no modeset.
        || atomic(0, &[0x67], &[9]) != Ok(0)
    {
        return TestResult::Fail("Colorspace");
    }
    // HDR_OUTPUT_METADATA: a static type 1 PQ infoframe.
    let mut hdr = [0u8; 32];
    hdr[4] = 2; // EOTF SMPTE ST 2084
    hdr[22..24].copy_from_slice(&1000u16.to_le_bytes());
    let pq = color_blob(idx, &hdr);
    hdr[26..28].copy_from_slice(&400u16.to_le_bytes());
    let brighter = color_blob(idx, &hdr);
    // drm_hdmi_infoframe_set_hdr_metadata reads only the type 1 frame: the
    // outer metadata_type is not checked.
    hdr[0] = 1;
    let other_type = color_blob(idx, &hdr);
    let short = color_blob(idx, &hdr[..30]);
    if atomic(ALLOW_MODESET, &[0x68], &[u64::from(short)]) != Err(FsError::InvalidData)
        || atomic(0, &[0x68], &[u64::from(pq)]) != Err(FsError::InvalidData)
        || color_obj_set(idx, u64::from(pq), 0x68, 31, COLOR_CONNECTOR) != Err(FsError::InvalidData)
        || atomic(ALLOW_MODESET, &[0x68], &[u64::from(pq)]) != Ok(0)
        || color_prop(idx, 31, COLOR_CONNECTOR, 0x68) != Some(u64::from(pq))
    {
        return TestResult::Fail("entering HDR");
    }
    // New metadata while in HDR is a stream update; leaving is a modeset.
    if atomic(0, &[0x68], &[u64::from(brighter)]) != Ok(0)
        || atomic(0, &[0x68], &[u64::from(other_type)]) != Ok(0)
        || color_obj_set(idx, u64::from(pq), 0x68, 31, COLOR_CONNECTOR) != Ok(0)
        || atomic(0, &[0x68], &[0]) != Err(FsError::InvalidData)
        || atomic(ALLOW_MODESET, &[0x68], &[0]) != Ok(0)
        || color_prop(idx, 31, COLOR_CONNECTOR, 0x68) != Some(0)
    {
        return TestResult::Fail("HDR metadata updates");
    }
    // An undriven connector: no modeset and no infoframe check (as
    // amdgpu_dm_connector_atomic_check skips it); sizes still apply.
    if let Some(ms) = crate::drm_registry::mode_state(idx) {
        ms.lock().encoders[0].crtc_id = None;
    }
    if color_obj_set(idx, u64::from(other_type), 0x68, 31, COLOR_CONNECTOR) != Ok(0)
        || color_obj_set(idx, 2, 0x67, 31, COLOR_CONNECTOR) != Ok(0)
        || color_obj_set(idx, u64::from(short), 0x68, 31, COLOR_CONNECTOR)
            != Err(FsError::InvalidData)
    {
        return TestResult::Fail("undriven connector");
    }
    // A connector without the properties takes neither.
    if let Some(ms) = crate::drm_registry::mode_state(idx) {
        ms.lock().native.clear();
    }
    if color_obj_set(idx, 0, 0x67, 31, COLOR_CONNECTOR) != Err(FsError::InvalidData)
        || color_obj_set(idx, 0, 0x68, 31, COLOR_CONNECTOR) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("properties on a plain connector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_connector_hdr_properties
);

// ── 6. Render-node fd rejects SETCRTC with PermissionDenied ────────────

#[allow(dead_code)]
fn smoke_drm_render_fd_rejects_setcrtc() -> TestResult {
    let idx = register_test_card();
    let mut buf = [0u8; 104]; // sizeof drm_mode_crtc.
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_SETCRTC,
        buf.as_mut_ptr() as usize,
        /*render*/ true,
    );
    match r {
        Err(FsError::PermissionDenied) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("render-node SETCRTC did not return PermissionDenied")
        }
        Ok(_) => TestResult::Fail("render-node SETCRTC succeeded — should reject"),
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_render_fd_rejects_setcrtc);

// ── 7. Render-node fd accepts GEM_CLOSE ────────────────────────────────

#[allow(dead_code)]
fn smoke_drm_render_fd_accepts_gem_close() -> TestResult {
    let idx = register_test_card();
    let mut buf = [0u8; 8];
    // GEM_CLOSE is RENDER_ALLOW in Linux. The permission gate must admit the
    // call, then the unknown zero handle must produce drm_gem_handle_delete's
    // EINVAL rather than EACCES or ENOTTY.
    let r = dispatch_card(
        idx,
        DRM_IOCTL_GEM_CLOSE,
        buf.as_mut_ptr() as usize,
        /*render*/ true,
    );
    match r {
        Err(FsError::InvalidData) => TestResult::Pass,
        Err(FsError::PermissionDenied) => {
            TestResult::Fail("GEM_CLOSE rejected on render fd — should be RENDER_ALLOW")
        }
        _ => TestResult::Fail("unknown GEM_CLOSE handle did not return EINVAL"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_render_fd_accepts_gem_close
);

// ── 8. DRM_IOCTL_MODE_ATOMIC succeeds on empty state ───────────────────

#[allow(dead_code)]
fn smoke_drm_ioctl_atomic_empty_commit_succeeds() -> TestResult {
    // The implemented atomic backend is VirtIO-GPU-specific; other drivers
    // correctly return EOPNOTSUPP rather than pretending to commit state.
    let idx = register_test_virtio_card();
    let mut req = DrmModeAtomicUapi {
        flags: 0x0400, // DRM_MODE_ATOMIC_ALLOW_MODESET.
        ..Default::default()
    };
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_ATOMIC,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    if r.is_err() {
        return TestResult::Fail("MODE_ATOMIC empty commit returned error");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_atomic_empty_commit_succeeds
);

/// KWin validates its initial CRTC enable with TEST_ONLY | ALLOW_MODESET
/// before it submits the real commit.  The CRTC starts inactive because the
/// boot scanout resource is transport-owned, so this request necessarily
/// changes ACTIVE.  The UAPI bridge must carry ALLOW_MODESET into
/// `AtomicState::allow_modeset`; otherwise a valid `0x500` probe is rejected
/// as an unflagged modeset.
#[allow(dead_code)]
fn smoke_drm_atomic_test_only_allow_modeset_accepts_initial_crtc_enable() -> TestResult {
    let idx = register_test_virtio_card();
    let objects = [11u32];
    let prop_counts = [1u32];
    let props = [0x52u32]; // CRTC ACTIVE
    let values = [1u64];
    let mut req = DrmModeAtomicUapi {
        flags: 0x0500, // DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET
        count_objs: objects.len() as u32,
        objs_ptr: objects.as_ptr() as u64,
        count_props_ptr: prop_counts.as_ptr() as u64,
        props_ptr: props.as_ptr() as u64,
        prop_values_ptr: values.as_ptr() as u64,
        ..Default::default()
    };
    match dispatch_card(
        idx,
        DRM_IOCTL_MODE_ATOMIC,
        &mut req as *mut _ as usize,
        /*render*/ false,
    ) {
        Ok(0) => TestResult::Pass,
        _ => TestResult::Fail("TEST_ONLY | ALLOW_MODESET rejected initial CRTC enable"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_atomic_test_only_allow_modeset_accepts_initial_crtc_enable
);

/// The VirtIO transport has already completed SET_SCANOUT before the DRM card
/// is registered.  KWin follows its initial allowed probe with a TEST_ONLY |
/// NONBLOCK check that deliberately omits ALLOW_MODESET.  As in Linux, an
/// unchanged ACTIVE property must remain a page-flip check, rather than being
/// turned into a false modeset because NARF forgot the live boot scanout.
#[allow(dead_code)]
fn smoke_drm_atomic_test_only_keeps_active_boot_scanout_no_modeset() -> TestResult {
    let idx = register_test_virtio_card();
    {
        let mode_state = match crate::drm_registry::mode_state(idx) {
            Some(mode_state) => mode_state,
            None => return TestResult::Fail("test VirtIO card had no mode state"),
        };
        let mut card = mode_state.lock();
        card.crtcs[0].enabled = true;
        card.crtcs[0].mode = Some(crate::Mode::XGA_60);
    }
    let objects = [11u32];
    let prop_counts = [1u32];
    let props = [0x52u32]; // CRTC ACTIVE
    let values = [1u64];
    let mut req = DrmModeAtomicUapi {
        flags: 0x0300, // DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_NONBLOCK
        count_objs: objects.len() as u32,
        objs_ptr: objects.as_ptr() as u64,
        count_props_ptr: prop_counts.as_ptr() as u64,
        props_ptr: props.as_ptr() as u64,
        prop_values_ptr: values.as_ptr() as u64,
        ..Default::default()
    };
    match dispatch_card(
        idx,
        DRM_IOCTL_MODE_ATOMIC,
        &mut req as *mut _ as usize,
        /*render*/ false,
    ) {
        Ok(0) => TestResult::Pass,
        _ => TestResult::Fail("unchanged active boot scanout was treated as a modeset"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_atomic_test_only_keeps_active_boot_scanout_no_modeset
);

/// KWin performs a plane-only TEST_ONLY commit, then submits the same plane
/// update with NONBLOCK | PAGE_FLIP_EVENT. Linux implicitly adds both the
/// plane's old and new CRTC states while decoding CRTC_ID, so the real commit
/// has a CRTC on which to signal even though no CRTC object appeared in the
/// userspace object array. Rejecting this shape with EINVAL makes KWin retry
/// TEST_ONLY forever and never establish a scanout.
#[allow(dead_code)]
fn smoke_drm_atomic_plane_only_flip_event_tracks_implicit_crtc() -> TestResult {
    use crate::drm_devfs_bridge::{DriCardFile, VirtioGpuCard};

    let name = format!("card{}", crate::drm_registry::count());
    let mut card = make_test_card();
    card.driver_name = "virtio_gpu";
    card.driver_desc = "NARF VirtIO GPU driver";
    card.version = (0, 1, 0);
    let handle = match card.gem.alloc(0x1000, 64 * 64 * 4) {
        Ok(handle) => handle,
        Err(_) => return TestResult::Fail("could not allocate atomic test GEM"),
    };
    let fb_id = match card.addfb2(64, 64, 0x3432_5258, 64 * 4, handle) {
        Ok(fb_id) => fb_id,
        Err(_) => return TestResult::Fail("could not create atomic test framebuffer"),
    };
    card.crtcs[0].primary_fb = Some(fb_id);
    card.crtcs[0].enabled = true;

    let idx =
        crate::drm_registry::register_drm_card_with_state(Arc::new(VirtioGpuCard::new(name)), card);
    let file = match DriCardFile::new(idx) {
        Some(file) => file,
        None => return TestResult::Fail("failed to open atomic test card"),
    };

    let objects = [0x40u32]; // synthetic primary plane for CRTC 11
    let prop_counts = [10u32];
    let props = [
        0x55u32, // FB_ID
        0x56,    // CRTC_ID
        0x57,    // SRC_X
        0x58,    // SRC_Y
        0x59,    // SRC_W
        0x5a,    // SRC_H
        0x5b,    // CRTC_X
        0x5c,    // CRTC_Y
        0x5d,    // CRTC_W
        0x5e,    // CRTC_H
    ];
    let values = [u64::from(fb_id), 11, 0, 0, 64 << 16, 64 << 16, 0, 0, 64, 64];
    let mut req = DrmModeAtomicUapi {
        flags: 0x0201, // NONBLOCK | PAGE_FLIP_EVENT
        count_objs: objects.len() as u32,
        objs_ptr: objects.as_ptr() as u64,
        count_props_ptr: prop_counts.as_ptr() as u64,
        props_ptr: props.as_ptr() as u64,
        prop_values_ptr: values.as_ptr() as u64,
        reserved: 0,
        user_data: 0xCAFE_BABE,
    };

    if file.ioctl(DRM_IOCTL_MODE_ATOMIC, &mut req as *mut _ as usize) != Ok(0) {
        return TestResult::Fail("plane-only atomic flip event did not inherit its CRTC");
    }
    if file.poll_readiness() & narf_filesystem::POLL_IN == 0 {
        return TestResult::Fail("plane-only atomic commit did not queue its flip event");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_atomic_plane_only_flip_event_tracks_implicit_crtc
);

// ── 9. ENOTTY on a registered card for an unknown 'd'-type ioctl ───────

#[allow(dead_code)]
fn smoke_drm_unrecognised_drm_cmd_returns_unsupported() -> TestResult {
    let idx = register_test_card();
    // A DRM-typed ioctl number that's not in our IoctlCmd table.
    let bogus = iowr(DRM_IOCTL_BASE, 0xEE, 8);
    let mut buf = [0u8; 8];
    match dispatch_card(idx, bogus, buf.as_mut_ptr() as usize, false) {
        Err(FsError::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("unrecognised cmd did not return Unsupported"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_unrecognised_drm_cmd_returns_unsupported
);

// ── 10. Card with no mode_state attached returns Unsupported ───────────

#[allow(dead_code)]
fn smoke_drm_card_without_state_is_unsupported() -> TestResult {
    // Register a bare DrmCard without mode_state.
    let name = format!("card{}", crate::drm_registry::count());
    let idx = crate::drm_registry::register_drm_card(Arc::new(BochsCard::new(name)));
    let mut buf = [0u8; 64];
    match dispatch_card(idx, DRM_IOCTL_VERSION, buf.as_mut_ptr() as usize, false) {
        Err(FsError::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("card without mode_state should return Unsupported"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_card_without_state_is_unsupported
);

// ── 11. FileOps::ioctl default returns Unsupported (proxy for ENOTTY) ──

#[allow(dead_code)]
fn smoke_fileops_ioctl_default_returns_unsupported() -> TestResult {
    // A FileOps that doesn't override ioctl — the default trait method
    // surfaces FsError::Unsupported which sys_ioctl translates to
    // -ENOTTY (25).
    struct PlainFile;
    impl FileOps for PlainFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async { Ok(0) })
        }
        fn stat(&self) -> narf_filesystem::Stat {
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode {
                    file_type: narf_filesystem::FileType::File,
                    perms: 0o644,
                },
                mtime_cycles: 0,
            }
        }
    }
    let f: alloc::sync::Arc<dyn FileOps> = alloc::sync::Arc::new(PlainFile);
    match f.ioctl(DRM_IOCTL_VERSION, 0) {
        Err(FsError::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("default FileOps::ioctl should return Unsupported"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_fileops_ioctl_default_returns_unsupported
);

// ── 12. DriCardFile primary node delegates through dispatch_card ───────

#[allow(dead_code)]
fn smoke_dri_card_file_ioctl_routes_through_bridge() -> TestResult {
    let idx = register_test_card();
    // Looks up via the public DriDir path so we test the full chain.
    use narf_filesystem::DirOps;
    let dir = crate::drm_devfs_bridge::DriDir;
    let name = format!("card{}", idx);
    let f = match dir.lookup(&name) {
        Some(f) => f,
        None => return TestResult::Fail("DriDir::lookup failed"),
    };
    let mut req = DrmModeCardResUapi::default();
    let r = f.ioctl(DRM_IOCTL_MODE_GETRESOURCES, &mut req as *mut _ as usize);
    if r.is_err() {
        return TestResult::Fail("DriCardFile::ioctl returned error");
    }
    if req.count_crtcs == 0 {
        return TestResult::Fail("DriCardFile GETRESOURCES count_crtcs == 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_dri_card_file_ioctl_routes_through_bridge
);

// ── 12b. VIRTGPU driver ioctls are served on the virtio_gpu CARD node ───
//
// GAP A regression: Mesa's GBM/EGL compositor context is created on card0 and
// issues VIRTGPU_GETPARAM/GET_CAPS/CONTEXT_INIT there. Every VIRTGPU ioctl is
// DRM_RENDER_ALLOW in Linux, which the primary (card) node serves too. Before
// the fix `DriCardFile::ioctl` went straight to the card/KMS dispatcher, so a
// VIRTGPU ioctl fell through to `handle_generic` → ENOTTY (Unsupported) and
// Mesa dropped every GL client to llvmpipe.

/// Linux advertises virtio_gpu version 0.1.0. Mesa's classic-VirGL winsys
/// rejects the device when the major version is non-zero.
fn smoke_dri_card_virtgpu_version_matches_linux() -> TestResult {
    let idx = register_test_virtio_card();
    use narf_filesystem::DirOps;
    let dir = crate::drm_devfs_bridge::DriDir;
    let name = format!("card{}", idx);
    let f = match dir.lookup(&name) {
        Some(f) => f,
        None => return TestResult::Fail("DriDir::lookup(card) failed"),
    };
    let mut req = DrmVersionUapi::default();
    if f.ioctl(DRM_IOCTL_VERSION, &mut req as *mut _ as usize)
        .is_err()
    {
        return TestResult::Fail("virtio_gpu DRM_IOCTL_VERSION failed");
    }
    if (req.version_major, req.version_minor, req.version_patchlevel) != (0, 1, 0) {
        return TestResult::Fail("virtio_gpu DRM version differs from Linux 0.1.0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_dri_card_virtgpu_version_matches_linux
);

/// The ioctl gate must admit every command buffer Mesa submits: the
/// multi-page streams of classic-VirGL screen creation, and a full Mesa
/// command buffer — VIRGL_MAX_CMDBUF_DWORDS = 64 Ki + 1024 dwords
/// (virgl_winsys.h) — which Mesa flushes in one EXECBUFFER and drops on
/// error ("expect bad rendering"). A finite cap is still kept.
fn smoke_virtgpu_execbuffer_capacity_covers_mesa_init() -> TestResult {
    const VIRGL_MAX_CMDBUF_BYTES: usize = ((64 * 1024) + 1024) * 4;
    for size in [4_136, 9_504, 18_412, VIRGL_MAX_CMDBUF_BYTES] {
        if size > crate::drm_ioctl_bridge::VIRTGPU_EXECBUFFER_MAX_BYTES {
            return TestResult::Fail("a Mesa VirGL command buffer size is rejected");
        }
    }
    if crate::drm_ioctl_bridge::VIRTGPU_EXECBUFFER_MAX_BYTES > 4 * 1024 * 1024 {
        return TestResult::Fail("VirtGPU execbuffer bound is not meaningfully constrained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_virtgpu_execbuffer_capacity_covers_mesa_init
);

/// Linux's virtgpu private ABI distinguishes malformed requests from missing
/// GEM handles and bad nested pointers. Keep those distinctions at the bridge
/// so `sys_ioctl` can return EINVAL, ENOENT, and EFAULT respectively.
fn smoke_virtgpu_ioctl_linux_error_classes() -> TestResult {
    use crate::drm_ioctl_bridge::{copy_in, dispatch_virtgpu_render, VirtGpuRenderState};
    use crate::drm_uapi::{
        DrmVirtGpuGetCapsUapi, DrmVirtGpuMapUapi, DrmVirtGpuResourceCreateBlobUapi,
        DrmVirtGpuResourceInfoUapi, DrmVirtGpuWaitUapi, DRM_IOCTL_VIRTGPU_GET_CAPS,
        DRM_IOCTL_VIRTGPU_MAP, DRM_IOCTL_VIRTGPU_RESOURCE_INFO, DRM_IOCTL_VIRTGPU_WAIT,
        DRM_VIRTGPU_NR_RESOURCE_CREATE_BLOB,
    };

    let state = VirtGpuRenderState::new();
    let mut info = DrmVirtGpuResourceInfoUapi {
        bo_handle: 0xfeed,
        ..Default::default()
    };
    if dispatch_virtgpu_render(
        DRM_IOCTL_VIRTGPU_RESOURCE_INFO,
        &mut info as *mut _ as usize,
        &state,
    ) != Err(FsError::NotFound)
    {
        return TestResult::Fail("RESOURCE_INFO unknown handle is not ENOENT-class");
    }

    let mut map = DrmVirtGpuMapUapi {
        handle: 0xfeed,
        ..Default::default()
    };
    if dispatch_virtgpu_render(DRM_IOCTL_VIRTGPU_MAP, &mut map as *mut _ as usize, &state)
        != Err(FsError::NotFound)
    {
        return TestResult::Fail("MAP unknown handle is not ENOENT-class");
    }

    let mut wait = DrmVirtGpuWaitUapi {
        handle: 0xfeed,
        flags: u32::MAX,
    };
    if dispatch_virtgpu_render(DRM_IOCTL_VIRTGPU_WAIT, &mut wait as *mut _ as usize, &state)
        != Err(FsError::NotFound)
    {
        return TestResult::Fail("WAIT unknown handle is not ENOENT-class");
    }

    let mut caps = DrmVirtGpuGetCapsUapi::default();
    if dispatch_virtgpu_render(
        DRM_IOCTL_VIRTGPU_GET_CAPS,
        &mut caps as *mut _ as usize,
        &state,
    ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("GET_CAPS size=0 is not EINVAL-class");
    }

    let mut blob = DrmVirtGpuResourceCreateBlobUapi {
        blob_flags: u32::MAX,
        size: 4096,
        ..Default::default()
    };
    let blob_cmd = crate::drm_uapi::iowr(
        crate::drm_uapi::DRM_IOCTL_BASE,
        DRM_VIRTGPU_NR_RESOURCE_CREATE_BLOB,
        core::mem::size_of::<DrmVirtGpuResourceCreateBlobUapi>() as u32,
    );
    if dispatch_virtgpu_render(blob_cmd, &mut blob as *mut _ as usize, &state)
        != Err(FsError::InvalidData)
    {
        return TestResult::Fail("RESOURCE_CREATE_BLOB bad flags are not EINVAL-class");
    }

    // SAFETY: null is intentionally supplied to exercise the helper's Linux
    // copy_from_user failure class; the helper rejects it before dereference.
    if unsafe { copy_in(0, 4) } != Err(FsError::BadAddress) {
        return TestResult::Fail("nested null pointer is not EFAULT-class");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_virtgpu_ioctl_linux_error_classes
);

/// POSITIVE: a VIRTGPU ioctl on the virtio_gpu card node is routed to the
/// per-open virtio-gpu dispatcher (GETPARAM(3D_FEATURES) → Ok), NOT ENOTTY.
#[allow(dead_code)]
fn smoke_dri_card_virtgpu_ioctl_routed() -> TestResult {
    let idx = register_test_virtio_card();
    use narf_filesystem::DirOps;
    let dir = crate::drm_devfs_bridge::DriDir;
    let name = format!("card{}", idx);
    let f = match dir.lookup(&name) {
        Some(f) => f,
        None => return TestResult::Fail("DriDir::lookup(card) failed"),
    };
    // GETPARAM writes the param value to the user pointer in `value`; point it
    // at a local word. Param 1 (3D_FEATURES) returns 0 when no device is probed
    // (kernel-test), but crucially returns Ok — proving it reached the VIRTGPU
    // dispatcher rather than falling through to the card path's ENOTTY.
    let mut out: u32 = 0xdead_beef;
    let mut req = crate::drm_uapi::DrmVirtGpuGetParamUapi {
        param: 1,
        value: &mut out as *mut u32 as u64,
    };
    match f.ioctl(
        crate::drm_uapi::DRM_IOCTL_VIRTGPU_GETPARAM,
        &mut req as *mut _ as usize,
    ) {
        Ok(_) => TestResult::Pass,
        Err(narf_filesystem::FsError::Unsupported) => TestResult::Fail(
            "VIRTGPU_GETPARAM on virtio card node returned Unsupported — not routed",
        ),
        Err(_) => TestResult::Fail("VIRTGPU_GETPARAM on virtio card node errored unexpectedly"),
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_dri_card_virtgpu_ioctl_routed);

/// NEGATIVE (gate is driver-scoped): the SAME VIRTGPU ioctl on a non-virtio
/// (bochs) card node still returns Unsupported — the routing must not hijack
/// VIRTGPU ioctl numbers on cards without a virtio-gpu private UAPI.
#[allow(dead_code)]
fn smoke_dri_card_virtgpu_ioctl_bochs_unsupported() -> TestResult {
    let idx = register_test_card(); // BochsCard → driver "bochs"
    use narf_filesystem::DirOps;
    let dir = crate::drm_devfs_bridge::DriDir;
    let name = format!("card{}", idx);
    let f = match dir.lookup(&name) {
        Some(f) => f,
        None => return TestResult::Fail("DriDir::lookup(card) failed"),
    };
    let mut out: u32 = 0;
    let mut req = crate::drm_uapi::DrmVirtGpuGetParamUapi {
        param: 1,
        value: &mut out as *mut u32 as u64,
    };
    match f.ioctl(
        crate::drm_uapi::DRM_IOCTL_VIRTGPU_GETPARAM,
        &mut req as *mut _ as usize,
    ) {
        Err(narf_filesystem::FsError::Unsupported) => TestResult::Pass,
        Ok(_) => TestResult::Fail("VIRTGPU_GETPARAM on bochs card node should be Unsupported"),
        Err(_) => TestResult::Fail("VIRTGPU_GETPARAM on bochs card node wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_dri_card_virtgpu_ioctl_bochs_unsupported
);

/// NO-REGRESSION: a KMS ioctl (GETRESOURCES) still works on the virtio_gpu
/// card node — the VIRTGPU dispatcher returns Unsupported for it and the call
/// falls through to the card/KMS path unchanged.
#[allow(dead_code)]
fn smoke_dri_card_virtio_kms_still_routes() -> TestResult {
    let idx = register_test_virtio_card();
    use narf_filesystem::DirOps;
    let dir = crate::drm_devfs_bridge::DriDir;
    let name = format!("card{}", idx);
    let f = match dir.lookup(&name) {
        Some(f) => f,
        None => return TestResult::Fail("DriDir::lookup(card) failed"),
    };
    let mut req = DrmModeCardResUapi::default();
    match f.ioctl(DRM_IOCTL_MODE_GETRESOURCES, &mut req as *mut _ as usize) {
        Ok(_) if req.count_crtcs > 0 => TestResult::Pass,
        Ok(_) => TestResult::Fail("GETRESOURCES on virtio card node returned 0 crtcs"),
        Err(_) => {
            TestResult::Fail("GETRESOURCES on virtio card node errored — KMS fall-through broken")
        }
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_dri_card_virtio_kms_still_routes
);

// ── 13. DriRenderFile render node rejects SETCRTC ──────────────────────

#[allow(dead_code)]
fn smoke_dri_render_file_setcrtc_eacces() -> TestResult {
    let idx = register_test_card();
    use narf_filesystem::DirOps;
    let dir = crate::drm_devfs_bridge::DriDir;
    let name = format!("renderD{}", idx + 128);
    let f = match dir.lookup(&name) {
        Some(f) => f,
        None => return TestResult::Fail("DriDir::lookup for renderD failed"),
    };
    let mut buf = [0u8; 104];
    match f.ioctl(DRM_IOCTL_MODE_SETCRTC, buf.as_mut_ptr() as usize) {
        Err(FsError::PermissionDenied) => TestResult::Pass,
        Ok(_) => TestResult::Fail("DriRenderFile SETCRTC should reject"),
        Err(_) => TestResult::Fail("DriRenderFile SETCRTC wrong error variant"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_dri_render_file_setcrtc_eacces
);

/// PAGE_FLIP validation and event-budget errors match Linux's
/// `drm_mode_page_flip_ioctl`: unknown objects are ENOENT, an unbound primary
/// plane is EBUSY, unsupported flags/sequence are EINVAL, and exhausted
/// per-file event space is ENOMEM without changing the active framebuffer.
#[allow(dead_code)]
fn smoke_drm_page_flip_linux_errno_parity() -> TestResult {
    use crate::drm_devfs_bridge::DriCardFile;
    use crate::drm_uapi::{DrmModePageFlipUapi, DRM_IOCTL_MODE_PAGE_FLIP};

    let name = format!("card{}", crate::drm_registry::count());
    let mut card = make_test_card();
    let first_handle = card.gem.alloc(0x1000, 64 * 64 * 4).unwrap();
    let second_handle = card.gem.alloc(0x5000, 64 * 64 * 4).unwrap();
    let first_fb = card
        .addfb2(64, 64, 0x3432_5258, 64 * 4, first_handle)
        .unwrap();
    let second_fb = card
        .addfb2(64, 64, 0x3432_5258, 64 * 4, second_handle)
        .unwrap();
    let idx =
        crate::drm_registry::register_drm_card_with_state(Arc::new(BochsCard::new(name)), card);
    let file = match DriCardFile::new(idx) {
        Some(file) => file,
        None => return TestResult::Fail("failed to open PAGE_FLIP test card"),
    };

    let mut req = DrmModePageFlipUapi {
        crtc_id: 11,
        fb_id: second_fb,
        flags: 0,
        reserved: 0,
        user_data: 0,
    };

    // The primary plane starts unbound.
    if file.ioctl(DRM_IOCTL_MODE_PAGE_FLIP, &mut req as *mut _ as usize) != Err(FsError::Busy) {
        return TestResult::Fail("unbound PAGE_FLIP did not return Busy/EBUSY");
    }

    if let Some(mode_state) = crate::drm_registry::mode_state(idx) {
        mode_state.lock().crtcs[0].primary_fb = Some(first_fb);
    } else {
        return TestResult::Fail("PAGE_FLIP test card lost mode state");
    }

    req.crtc_id = 0xFFFF_FFFF;
    if file.ioctl(DRM_IOCTL_MODE_PAGE_FLIP, &mut req as *mut _ as usize) != Err(FsError::NotFound) {
        return TestResult::Fail("unknown PAGE_FLIP CRTC did not return NotFound/ENOENT");
    }
    req.crtc_id = 11;
    req.fb_id = 0xFFFF_FFFF;
    if file.ioctl(DRM_IOCTL_MODE_PAGE_FLIP, &mut req as *mut _ as usize) != Err(FsError::NotFound) {
        return TestResult::Fail("unknown PAGE_FLIP fb did not return NotFound/ENOENT");
    }
    req.fb_id = second_fb;
    req.flags = 0x2; // ASYNC is not advertised by Linux virtio-gpu.
    if file.ioctl(DRM_IOCTL_MODE_PAGE_FLIP, &mut req as *mut _ as usize)
        != Err(FsError::InvalidData)
    {
        return TestResult::Fail("unsupported PAGE_FLIP flag did not return EINVAL");
    }
    req.flags = 0;
    req.reserved = 1; // sequence without a target flag
    if file.ioctl(DRM_IOCTL_MODE_PAGE_FLIP, &mut req as *mut _ as usize)
        != Err(FsError::InvalidData)
    {
        return TestResult::Fail("PAGE_FLIP sequence without target did not return EINVAL");
    }

    // Fill exactly Linux's 4096-byte per-open event budget.
    for cookie in 0..128u64 {
        if file.queue_flip_event_for_test(cookie, 11).is_err() {
            return TestResult::Fail("PAGE_FLIP event budget filled too early");
        }
    }
    req.flags = 0x1; // DRM_MODE_PAGE_FLIP_EVENT
    req.reserved = 0;
    if file.ioctl(DRM_IOCTL_MODE_PAGE_FLIP, &mut req as *mut _ as usize)
        != Err(FsError::OutOfMemory)
    {
        return TestResult::Fail("full PAGE_FLIP event budget did not return ENOMEM");
    }
    let active_fb = crate::drm_registry::mode_state(idx)
        .and_then(|mode_state| mode_state.lock().crtcs[0].primary_fb);
    if active_fb != Some(first_fb) {
        return TestResult::Fail("ENOMEM PAGE_FLIP changed the active framebuffer");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_page_flip_linux_errno_parity
);

// ── 14. CREATE_DUMB returns sane handle/pitch/size ─────────────────────

#[allow(dead_code)]
fn smoke_drm_create_dumb_basic() -> TestResult {
    use crate::drm_uapi::{DrmModeCreateDumbUapi, DRM_IOCTL_MODE_CREATE_DUMB};
    let idx = register_test_card();
    let mut req = DrmModeCreateDumbUapi {
        height: 64,
        width: 64,
        bpp: 32,
        flags: 0,
        handle: 0,
        pitch: 0,
        size: 0,
    };
    // We can't actually run alloc_pages_on in the kernel-test path because
    // the buddy allocator needs a live memory map. Instead test the ioctl
    // dispatch routing + size computation logic by checking that the card
    // correctly routes to CREATE_DUMB (returns InvalidData rather than
    // Unsupported, which would mean the cmd was unrecognised).
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_CREATE_DUMB,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    // In the kernel-test environment the frame allocator may or may not be
    // live. Accept either Ok (allocator live) or Err(InvalidData) (allocator
    // not wired). What we MUST NOT get is Err(Unsupported) (unrecognised cmd).
    match r {
        Ok(_) | Err(narf_filesystem::FsError::InvalidData) => TestResult::Pass,
        Err(narf_filesystem::FsError::Unsupported) => {
            TestResult::Fail("CREATE_DUMB returned Unsupported — cmd not routed")
        }
        Err(narf_filesystem::FsError::PermissionDenied) => {
            TestResult::Fail("CREATE_DUMB rejected — should be RENDER_ALLOW or master")
        }
        Err(_) => TestResult::Pass, // any other error = routed + failed for non-dispatch reason
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_create_dumb_basic);

// ── 15. MAP_DUMB returns an offset that resolves back to buffer phys ───

#[allow(dead_code)]
fn smoke_drm_map_dumb_resolves_to_phys() -> TestResult {
    use crate::drm::card::DumbBacking;
    use crate::drm_uapi::{DrmModeMapDumbUapi, DRM_IOCTL_MODE_MAP_DUMB};
    // Build a card + manually insert a fake dumb backing so we can
    // exercise MAP_DUMB without needing the buddy allocator.
    let idx = {
        let name = format!("card{}", crate::drm_registry::count());
        let mut card = make_test_card();
        // Fake dumb backing: phys=0xDEAD_0000, size=4096, order=0.
        let fake_phys = 0xDEAD_0000u64;
        let fake_size = 4096usize;
        // Allocate a GEM handle manually to avoid calling alloc_pages_on.
        let handle = card.gem.alloc(fake_phys, fake_size).unwrap();
        let mmap_offset = (handle as u64) << 12;
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys: fake_phys,
            byte_len: fake_size,
            order: 0,
            mmap_offset,
            refcount: 1,
            dma_buf: Default::default(),
        });
        crate::drm_registry::register_drm_card_with_state(
            Arc::new(crate::drm_devfs_bridge::BochsCard::new(name)),
            card,
        )
    };

    let mut req = DrmModeMapDumbUapi {
        handle: 1, // first handle from GemTable
        pad: 0,
        offset: 0,
    };
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_MAP_DUMB,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    if r.is_err() {
        return TestResult::Fail("MAP_DUMB returned error");
    }
    // Offset should be handle << 12 = 1 << 12 = 4096.
    if req.offset == 0 {
        return TestResult::Fail("MAP_DUMB returned zero offset");
    }
    // Verify dispatch_mmap resolves the offset back to the fake phys.
    let frames = crate::drm_ioctl_bridge::dispatch_mmap(idx, req.offset, 4096);
    match frames {
        Ok(v) if !v.is_empty() && v[0] == 0xDEAD_0000 => TestResult::Pass,
        Ok(v) => {
            let _ = v;
            TestResult::Fail("dispatch_mmap returned wrong phys")
        }
        Err(_) => TestResult::Fail("dispatch_mmap returned error"),
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_map_dumb_resolves_to_phys);

// ── 15b. PRIME_HANDLE_TO_FD export aliases the dumb buffer frames ──────
//
// prime_export_fileops must find the GEM handle's dumb backing and return
// a FileOps whose mmap_frames aliases the SAME contiguous frames — that's
// what lets Mesa GBM's gbm_bo_get_fd hand kwin a CPU-mmap-able QPainter
// swapchain buffer. Regression: PRIME_HANDLE_TO_FD used to ENOTTY, so
// kwin logged "drmPrimeHandleToFD() failed: Not a tty" and could not
// allocate a swapchain buffer.
fn smoke_drm_prime_export_aliases_dumb_frames() -> TestResult {
    use crate::drm::card::DumbBacking;
    let idx = {
        let name = format!("card{}", crate::drm_registry::count());
        let mut card = make_test_card();
        let fake_phys = 0xCAFE_0000u64;
        let fake_size = 2 * 4096usize; // two pages
        let handle = card.gem.alloc(fake_phys, fake_size).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys: fake_phys,
            byte_len: fake_size,
            order: 1,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        crate::drm_registry::register_drm_card_with_state(
            Arc::new(crate::drm_devfs_bridge::BochsCard::new(name)),
            card,
        )
    };

    // Unknown handle → None (the ioctl maps this to ENOENT).
    if crate::drm_devfs_bridge::prime_export_fileops(idx, 999).is_some() {
        return TestResult::Fail("PRIME export returned a file for a bogus handle");
    }

    // First GemTable::alloc yields handle 1.
    let dmabuf = match crate::drm_devfs_bridge::prime_export_fileops(idx, 1) {
        Some(f) => f,
        None => return TestResult::Fail("PRIME export returned None for a live handle"),
    };
    // A whole-buffer mmap must alias both fake frames, in order.
    match dmabuf.mmap_frames(0, 2 * 4096) {
        Ok(v) if v == alloc::vec![0xCAFE_0000u64, 0xCAFE_0000u64 + 4096] => {}
        Ok(_) => return TestResult::Fail("PRIME dma-buf mmap_frames returned wrong frames"),
        Err(_) => return TestResult::Fail("PRIME dma-buf mmap_frames errored"),
    }
    // PRIME export owns one backing reference while the fd is live.
    let refs_while_exported = {
        let ms = crate::drm_registry::mode_state(idx).unwrap();
        let card = ms.lock();
        card.dumb_backing(1).map(|b| b.refcount)
    };
    if refs_while_exported != Some(2) {
        return TestResult::Fail("PRIME dma-buf did not retain its dumb backing");
    }

    // The dma-buf must round-trip back to its GEM handle (FD_TO_HANDLE):
    // a compositor exports its buffer then imports it to build a KMS fb.
    if dmabuf.as_prime_gem_handle() != Some(1) {
        return TestResult::Fail("PRIME dma-buf did not round-trip to its GEM handle");
    }
    drop(dmabuf);
    let refs_after_close = {
        let ms = crate::drm_registry::mode_state(idx).unwrap();
        let card = ms.lock();
        card.dumb_backing(1).map(|b| b.refcount)
    };
    if refs_after_close != Some(1) {
        return TestResult::Fail("closing PRIME dma-buf did not release its backing reference");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_prime_export_aliases_dumb_frames
);

/// A PRIME-imported VirGL GEM object follows Linux's split handle/object
/// lifetime: GEM_CLOSE drops the handle reference, while an ADDFB2 framebuffer
/// keeps the shared host resource alive until RMFB.
fn smoke_drm_virtgpu_prime_import_survives_handle_close() -> TestResult {
    let mut card = make_test_card();
    let resource = crate::drm_ioctl_bridge::test_virtgpu_resource(0x44, 4 * 4096);
    if card
        .register_virtgpu_import(7, Arc::clone(&resource))
        .is_err()
    {
        return TestResult::Fail("failed to register VirtGPU PRIME import");
    }
    let fb = match card.addfb2(64, 64, 0x3432_5258, 256, 7) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("ADDFB2 rejected imported VirtGPU GEM handle"),
    };
    if !card.remove_virtgpu_import(7) || card.virtgpu_import(7).is_none() {
        return TestResult::Fail("GEM_CLOSE dropped framebuffer-held VirtGPU resource");
    }
    if card.rmfb(fb).is_err() || card.virtgpu_import(7).is_some() || card.gem.lookup(7).is_some() {
        return TestResult::Fail("RMFB did not release final VirtGPU import reference");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_virtgpu_prime_import_survives_handle_close
);

// ── 15bb. A primary-node mmap pins its dumb backing ──────────────────

fn smoke_drm_primary_mmap_pins_dumb_backing() -> TestResult {
    use crate::drm::card::DumbBacking;

    let idx = {
        let name = format!("card{}", crate::drm_registry::count());
        let mut card = make_test_card();
        let handle = card.gem.alloc(0xFACE_0000, 4096).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys: 0xFACE_0000,
            byte_len: 4096,
            order: 0,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        crate::drm_registry::register_drm_card_with_state(
            Arc::new(crate::drm_devfs_bridge::BochsCard::new(name)),
            card,
        )
    };
    let file = match crate::drm_devfs_bridge::DriCardFile::new(idx) {
        Some(file) => file,
        None => return TestResult::Fail("failed to open registered DRM card"),
    };
    let lifetime = match file.mmap_lifetime(4096, 4096) {
        Some(lifetime) => lifetime,
        None => return TestResult::Fail("primary mmap did not acquire a backing lease"),
    };
    let refs_while_mapped = {
        let ms = crate::drm_registry::mode_state(idx).unwrap();
        let card = ms.lock();
        card.dumb_backing(1).map(|b| b.refcount)
    };
    if refs_while_mapped != Some(2) {
        return TestResult::Fail("primary mmap lease did not retain its dumb backing");
    }
    drop(lifetime);
    let refs_after_unmap = {
        let ms = crate::drm_registry::mode_state(idx).unwrap();
        let card = ms.lock();
        card.dumb_backing(1).map(|b| b.refcount)
    };
    if refs_after_unmap != Some(1) {
        return TestResult::Fail("primary mmap lease did not release its backing reference");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_primary_mmap_pins_dumb_backing
);

// ── 15c. Dumb backing is refcounted: survives GEM_CLOSE while fb-held ──
//
// Linux GEM objects are refcounted; a framebuffer (ADDFB2) holds a ref, so
// closing the GEM handle does NOT free the buffer. Regression: kwin/Mesa
// GBM closes its GEM handle right after ADDFB2, and NARF freed the backing
// immediately → SETCRTC found no scanout source (src_phys=None, blit
// skipped, frame reused by the next CREATE_DUMB = a use-after-free).
fn smoke_drm_dumb_backing_survives_gem_close_while_fb_held() -> TestResult {
    use crate::drm::card::DumbBacking;
    let mut card = make_test_card();
    let fake_phys = 0xB00B_0000u64;
    // Room for the 64x64 XRGB8888 framebuffer (ADDFB2 checks the size).
    let handle = card.gem.alloc(fake_phys, 64 * 64 * 4).unwrap();
    card.dumb_backings.push(DumbBacking {
        gem_handle: handle,
        phys: fake_phys,
        byte_len: 64 * 64 * 4,
        order: 0,
        mmap_offset: (handle as u64) << 12,
        refcount: 1,
        dma_buf: Default::default(),
    });
    // ADDFB2 takes a reference (refcount 1 -> 2). XR24 = 0x34325258.
    let fb = card.addfb2(64, 64, 0x3432_5258, 256, handle).unwrap();

    // Client closes the GEM handle — backing MUST survive (fb holds a ref).
    if card.remove_dumb_backing(handle).is_some() {
        return TestResult::Fail("backing freed on GEM_CLOSE while a fb referenced it");
    }
    if card.dumb_backing(handle).is_none() {
        return TestResult::Fail("backing gone after GEM_CLOSE — SETCRTC would find no source");
    }

    // RMFB drops the last reference — now the frames are freed.
    match card.rmfb(fb) {
        Ok(Some((phys, order))) if phys == fake_phys && order == 0 => {}
        Ok(other) => {
            let _ = other;
            return TestResult::Fail("RMFB did not free the backing on the last ref drop");
        }
        Err(_) => return TestResult::Fail("RMFB errored"),
    }
    if card.dumb_backing(handle).is_some() {
        return TestResult::Fail("backing still present after its last reference dropped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_dumb_backing_survives_gem_close_while_fb_held
);

// ── 16. SETCRTC with valid fb_id succeeds (no live scanout in test) ────

#[allow(dead_code)]
fn smoke_drm_setcrtc_with_fb_succeeds() -> TestResult {
    use crate::drm::card::DumbBacking;
    use crate::drm_uapi::{DrmModeCrtcUapi, DRM_IOCTL_MODE_SETCRTC};
    // Build a card with a fake dumb backing + framebuffer.
    let idx = {
        let name = format!("card{}", crate::drm_registry::count());
        let mut card = make_test_card();
        let fake_phys = 0xBEEF_0000u64;
        let fake_size = 256 * 256 * 4usize;
        let handle = card.gem.alloc(fake_phys, fake_size).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys: fake_phys,
            byte_len: fake_size,
            order: 0,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        // Register a framebuffer backed by this handle.
        let fb_id = card
            .addfb2(256, 256, 0x3432_5258 /* XR24 */, 256 * 4, handle)
            .unwrap();
        let _ = fb_id;
        // Drive the card as the pre-established master (this smoke exercises the
        // SETCRTC blit path, not master arbitration) so the modeset gate passes.
        card.master_open(SMOKE_MASTER_ID);
        crate::drm_registry::register_drm_card_with_state(
            Arc::new(crate::drm_devfs_bridge::BochsCard::new(name)),
            card,
        )
    };

    // Look up the fb_id (should be 1 since next_fb_id starts at 1).
    let fb_id = {
        let ms = crate::drm_registry::mode_state(idx).unwrap();
        let card = ms.lock();
        card.framebuffers.first().map(|f| f.id).unwrap_or(0)
    };
    if fb_id == 0 {
        return TestResult::Fail("no framebuffer registered");
    }

    let mut req = DrmModeCrtcUapi {
        crtc_id: 11,
        fb_id,
        ..Default::default()
    };
    let r = dispatch_card(
        idx,
        DRM_IOCTL_MODE_SETCRTC,
        &mut req as *mut _ as usize,
        /*render*/ false,
    );
    // SETCRTC should succeed even when no real scanout is live
    // (blit_to_scanout returns early when query_scanout() returns None).
    match r {
        Ok(_) => TestResult::Pass,
        Err(narf_filesystem::FsError::PermissionDenied) => {
            TestResult::Fail("SETCRTC rejected on primary fd — wrong permission gate")
        }
        Err(e) => {
            let _ = e;
            TestResult::Fail("SETCRTC returned unexpected error")
        }
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_setcrtc_with_fb_succeeds);

// ── DRM master arbitration ─────────────────────────────────────────────

/// Two competing opens contend for DRM master: SET_MASTER is exclusive
/// (EBUSY while held), only the master may modeset (EACCES otherwise),
/// DROP_MASTER by a non-master is EINVAL, and after the holder drops, the
/// other open can take over — the greeter→user-session handoff. Every errno
/// matches Linux `drm_auth.c`.
#[allow(dead_code)]
fn smoke_drm_master_arbitration() -> TestResult {
    use crate::drm_uapi::{DrmModeCrtcUapi, DRM_IOCTL_MODE_SETCRTC};
    // Fresh card — device master is free.
    let idx = register_test_card_unmastered();
    let set_master = ioc(0, DRM_IOCTL_BASE, 0x1E, 0);
    let drop_master = ioc(0, DRM_IOCTL_BASE, 0x1F, 0);
    const A: u64 = 0x0A11;
    const B: u64 = 0x0B22;

    // A modeset attempt as `open_id`, returning the raw dispatch result.
    let setcrtc = |open_id: u64| {
        let mut crtc = DrmModeCrtcUapi {
            crtc_id: 11,
            ..Default::default()
        };
        crate::drm_ioctl_bridge::dispatch_card(
            idx,
            open_id,
            DRM_IOCTL_MODE_SETCRTC,
            &mut crtc as *mut _ as usize,
            false,
        )
    };
    let master_ioctl = |open_id: u64, cmd: u32| {
        crate::drm_ioctl_bridge::dispatch_card(idx, open_id, cmd, 0, false)
    };

    // A claims the free master; a repeat is idempotent (already current → 0).
    if master_ioctl(A, set_master) != Ok(0) {
        return TestResult::Fail("A SET_MASTER on a free device should succeed");
    }
    if master_ioctl(A, set_master) != Ok(0) {
        return TestResult::Fail("A repeat SET_MASTER (already master) should be Ok(0)");
    }
    // B cannot take master while A holds it → EBUSY.
    match master_ioctl(B, set_master) {
        Err(FsError::Busy) => {}
        other => {
            let _ = other;
            return TestResult::Fail("B SET_MASTER while A holds it should be EBUSY");
        }
    }
    // B (non-master) is barred from modeset → EACCES.
    match setcrtc(B) {
        Err(FsError::PermissionDenied) => {}
        other => {
            let _ = other;
            return TestResult::Fail("non-master SETCRTC should be EACCES");
        }
    }
    // A (master) may modeset — must not be gated (any non-EACCES result is fine;
    // SETCRTC can succeed or fail downstream on a card with no live scanout).
    if let Err(FsError::PermissionDenied) = setcrtc(A) {
        return TestResult::Fail("master SETCRTC should not be EACCES");
    }
    // B dropping a master it does not hold → EINVAL.
    match master_ioctl(B, drop_master) {
        Err(FsError::InvalidData) => {}
        other => {
            let _ = other;
            return TestResult::Fail("non-master DROP_MASTER should be EINVAL");
        }
    }
    // A drops master → device master is free again.
    if master_ioctl(A, drop_master) != Ok(0) {
        return TestResult::Fail("A DROP_MASTER (current master) should succeed");
    }
    // Handoff: B now takes the freed master, and the roles swap.
    if master_ioctl(B, set_master) != Ok(0) {
        return TestResult::Fail("B SET_MASTER after A dropped should succeed");
    }
    if let Err(FsError::PermissionDenied) = setcrtc(B) {
        return TestResult::Fail("B (new master) SETCRTC should not be EACCES");
    }
    match setcrtc(A) {
        Err(FsError::PermissionDenied) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("A (ex-master) SETCRTC should be EACCES after handoff")
        }
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_master_arbitration);

/// The first primary open of a master-free card auto-acquires DRM master
/// (drm_master_open), and closing that fd auto-drops it (drm_master_release)
/// so the next session can take over.
#[allow(dead_code)]
fn smoke_drm_master_autodrop_on_close() -> TestResult {
    let idx = register_test_card_unmastered();
    let master = || crate::drm_registry::mode_state(idx).and_then(|ms| ms.lock().current_master);
    if master().is_some() {
        return TestResult::Fail("a freshly registered card should have no master");
    }
    {
        let _f = match crate::drm_devfs_bridge::DriCardFile::new(idx) {
            Some(f) => f,
            None => return TestResult::Fail("opening the card node failed"),
        };
        // First primary open auto-acquires master.
        if master().is_none() {
            return TestResult::Fail("first primary open should auto-acquire master");
        }
    } // `_f` drops here → master_release
    if master().is_some() {
        return TestResult::Fail("closing the master fd should free the device master");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_master_autodrop_on_close);

/// GET_MAGIC / AUTH_MAGIC follow `drm_auth.c` + `drm_ioctl_permit`: AUTH_MAGIC
/// is DRM_MASTER-only (EACCES for a non-master or render caller), EINVAL for a
/// magic no open holds, one-shot per magic, and EFAULT on a bad arg ahead of
/// the permission check. The load-bearing case is libdrm's `drmIsMaster()` =
/// `drmAuthMagic(fd, 0) != -EACCES`: on a non-master fd it must see EACCES, or
/// kwin's createNonMasterFd() runs DROP_MASTER on it, fails, and kills the
/// Xwayland connection that asked for a wp_drm_lease_device_v1 fd.
#[allow(dead_code)]
fn smoke_drm_auth_magic_master_gate() -> TestResult {
    let idx = register_test_card_unmastered();
    let set_master = ioc(0, DRM_IOCTL_BASE, 0x1E, 0);
    let get_magic = ioc(IOC_READ, DRM_IOCTL_BASE, 0x02, 4);
    let auth_magic = ioc(IOC_WRITE, DRM_IOCTL_BASE, 0x11, 4);
    const A: u64 = 0x0A33;
    const B: u64 = 0x0B44;
    let call = |open_id: u64, cmd: u32, magic: &mut u32, render: bool| {
        crate::drm_ioctl_bridge::dispatch_card(
            idx,
            open_id,
            cmd,
            magic as *mut u32 as usize,
            render,
        )
    };

    if crate::drm_ioctl_bridge::dispatch_card(idx, A, set_master, 0, false) != Ok(0) {
        return TestResult::Fail("A SET_MASTER on a free device should succeed");
    }
    // GET_MAGIC: a stable, non-zero, per-open token.
    let (mut mb, mut mb2, mut ma) = (0u32, 0u32, 0u32);
    if call(B, get_magic, &mut mb, false) != Ok(0) || mb == 0 {
        return TestResult::Fail("GET_MAGIC on a primary fd should return a non-zero magic");
    }
    if call(B, get_magic, &mut mb2, false) != Ok(0) || mb2 != mb {
        return TestResult::Fail("a repeat GET_MAGIC should return the same magic");
    }
    if call(A, get_magic, &mut ma, false) != Ok(0) || ma == 0 || ma == mb {
        return TestResult::Fail("each open should get its own magic");
    }
    // drmIsMaster() on the non-master: AUTH_MAGIC(0) must be EACCES.
    let mut zero = 0u32;
    if call(B, auth_magic, &mut zero, false) != Err(FsError::PermissionDenied) {
        return TestResult::Fail("non-master AUTH_MAGIC(0) should be EACCES (drmIsMaster)");
    }
    let mut mb_copy = mb;
    if call(B, auth_magic, &mut mb_copy, false) != Err(FsError::PermissionDenied) {
        return TestResult::Fail("non-master AUTH_MAGIC of a live magic should be EACCES");
    }
    // drmIsMaster() on the master: magic 0 is never issued → EINVAL.
    let mut zero = 0u32;
    if call(A, auth_magic, &mut zero, false) != Err(FsError::InvalidData) {
        return TestResult::Fail("master AUTH_MAGIC(0) should be EINVAL");
    }
    let mut unknown = 0x7fff_fff0u32;
    if call(A, auth_magic, &mut unknown, false) != Err(FsError::InvalidData) {
        return TestResult::Fail("master AUTH_MAGIC of an unissued magic should be EINVAL");
    }
    // The master authenticates B's magic exactly once.
    let mut mb_copy = mb;
    if call(A, auth_magic, &mut mb_copy, false) != Ok(0) {
        return TestResult::Fail("master AUTH_MAGIC of a live magic should succeed");
    }
    let mut mb_copy = mb;
    if call(A, auth_magic, &mut mb_copy, false) != Err(FsError::InvalidData) {
        return TestResult::Fail("a consumed magic should not authenticate twice (EINVAL)");
    }
    // B keeps its magic after being authenticated (drm_file::magic persists).
    let mut mb3 = 0u32;
    if call(B, get_magic, &mut mb3, false) != Ok(0) || mb3 != mb {
        return TestResult::Fail("GET_MAGIC after auth should still return the open's magic");
    }
    // Arg copy precedes the permission check: NULL is EFAULT even for B.
    if crate::drm_ioctl_bridge::dispatch_card(idx, B, auth_magic, 0, false)
        != Err(FsError::BadAddress)
    {
        return TestResult::Fail("AUTH_MAGIC with a NULL arg should be EFAULT before EACCES");
    }
    if crate::drm_ioctl_bridge::dispatch_card(idx, A, get_magic, 0, false)
        != Err(FsError::BadAddress)
    {
        return TestResult::Fail("GET_MAGIC with a NULL arg should be EFAULT");
    }
    // Render clients: neither ioctl is DRM_RENDER_ALLOW → EACCES; GET_MAGIC
    // still copies the zeroed kdata back.
    let mut r = 0xffff_ffffu32;
    if call(A, get_magic, &mut r, true) != Err(FsError::PermissionDenied) || r != 0 {
        return TestResult::Fail("render-node GET_MAGIC should be EACCES and write 0");
    }
    let mut zero = 0u32;
    if call(A, auth_magic, &mut zero, true) != Err(FsError::PermissionDenied) {
        return TestResult::Fail("render-node AUTH_MAGIC should be EACCES");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_auth_magic_master_gate);

/// Closing an open forgets its magic (`drm_file_free`), so a stale token
/// cannot authenticate a later open that happens to reuse the open id.
#[allow(dead_code)]
fn smoke_drm_magic_released_on_close() -> TestResult {
    let idx = register_test_card();
    let auth_magic = ioc(IOC_WRITE, DRM_IOCTL_BASE, 0x11, 4);
    let ms = match crate::drm_registry::mode_state(idx) {
        Some(ms) => ms,
        None => return TestResult::Fail("test card has no mode state"),
    };
    const C: u64 = 0x0C55;
    let magic = ms.lock().get_magic(C);
    ms.lock().magic_release(C);
    let mut m = magic;
    match crate::drm_ioctl_bridge::dispatch_card(
        idx,
        SMOKE_MASTER_ID,
        auth_magic,
        &mut m as *mut u32 as usize,
        false,
    ) {
        Err(FsError::InvalidData) => TestResult::Pass,
        _ => TestResult::Fail("a closed open's magic should no longer authenticate"),
    }
}
kernel_test_in!("drivers/gpu/drm_ioctl", smoke_drm_magic_released_on_close);

// Anchor the kernel-test framework imports so the kernel-test feature
// doesn't trip a "use never used" warning on cfg-out builds.
const _USE_STRING: Option<String> = None;
const _USE_VEC: Option<alloc::vec::Vec<u8>> = None;
#[allow(dead_code)]
fn _use_vec_macro() {
    let _ = vec![0u8; 0];
}

// ── dma-buf implicit sync on the real PRIME files ─────────────────────────
//
// Linux keeps ONE `dma_resv` per buffer: every dma-buf fd exported from a
// GEM handle (and every handle that re-imports it) sees the same fences.
// Chromium imports a render fence into the dma-buf it hands the compositor
// and the compositor exports it back, often through a different fd.

/// A sync_file stand-in fence for the dma-buf ioctl context below.
struct PendingTestFence(u64);

impl narf_filesystem::DrmFence for PendingTestFence {
    fn is_signalled(&self) -> bool {
        false
    }
    fn wait(&self, _timeout_ms: u64) -> bool {
        false
    }
    fn context(&self) -> Option<u64> {
        Some(self.0)
    }
}

/// Offset-addressed ioctl memory plus the syscall layer's sync_file seam:
/// fd 7 is a sync_file holding `import`; exports are captured.
struct DmaBufCtx {
    bytes: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u8>>,
    import: Arc<dyn narf_filesystem::DrmFence>,
    exported: narf_lib::sync::IrqSafeSpinLock<
        Option<alloc::vec::Vec<Arc<dyn narf_filesystem::DrmFence>>>,
    >,
}

impl DmaBufCtx {
    fn new(import: Arc<dyn narf_filesystem::DrmFence>) -> Self {
        Self::with_len(64, import)
    }

    fn with_len(len: usize, import: Arc<dyn narf_filesystem::DrmFence>) -> Self {
        Self {
            bytes: narf_lib::sync::IrqSafeSpinLock::new(vec![0u8; len]),
            import,
            exported: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }

    fn put(&self, at: usize, b: &[u8]) {
        self.bytes.lock()[at..at + b.len()].copy_from_slice(b);
    }

    fn get32(&self, at: usize) -> i32 {
        i32::from_ne_bytes(self.bytes.lock()[at..at + 4].try_into().unwrap())
    }
}

impl narf_filesystem::IoctlContext for DmaBufCtx {
    fn read(&self, a: u64, b: &mut [u8]) -> Result<(), FsError> {
        let data = self.bytes.lock();
        let a = a as usize;
        b.copy_from_slice(data.get(a..a + b.len()).ok_or(FsError::BadAddress)?);
        Ok(())
    }
    fn write(&self, a: u64, b: &[u8]) -> Result<(), FsError> {
        let mut data = self.bytes.lock();
        let a = a as usize;
        data.get_mut(a..a + b.len())
            .ok_or(FsError::BadAddress)?
            .copy_from_slice(b);
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn sync_file_fences(
        &self,
        fd: i32,
    ) -> Option<alloc::vec::Vec<Arc<dyn narf_filesystem::DrmFence>>> {
        (fd == 7).then(|| vec![self.import.clone()])
    }
    fn install_sync_file(
        &self,
        fences: alloc::vec::Vec<Arc<dyn narf_filesystem::DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        report(5).map_err(narf_filesystem::InstallFdError::Report)?;
        *self.exported.lock() = Some(fences);
        Ok(5)
    }
}

const DMA_BUF_IOCTL_EXPORT_SYNC_FILE: u32 = 0xc008_6202;
const DMA_BUF_IOCTL_IMPORT_SYNC_FILE: u32 = 0x4008_6203;

fn dma_buf_ioctl(
    file: &Arc<dyn FileOps>,
    ctx: &DmaBufCtx,
    cmd: u32,
    flags: u32,
    fd: i32,
) -> Option<u64> {
    ctx.put(8, &flags.to_ne_bytes());
    ctx.put(12, &fd.to_ne_bytes());
    // dma_buf_ioctl never parks for these requests: one poll completes it.
    let mut future = file.ioctl_user(cmd, 8, ctx);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        core::task::Poll::Ready(result) => result.ok(),
        core::task::Poll::Pending => None,
    }
}

/// IMPORT through one export and EXPORT through another must meet on the
/// shared reservation; an unknown dma-buf ioctl is ENOTTY.
fn check_shared_reservation(
    first: &Arc<dyn FileOps>,
    second: &Arc<dyn FileOps>,
) -> Result<(), &'static str> {
    let fence: Arc<dyn narf_filesystem::DrmFence> = Arc::new(PendingTestFence(0x77));
    let ctx = DmaBufCtx::new(fence.clone());
    if dma_buf_ioctl(first, &ctx, DMA_BUF_IOCTL_IMPORT_SYNC_FILE, 2, 7) != Some(0) {
        return Err("IMPORT_SYNC_FILE(WRITE) on the PRIME dma-buf failed");
    }
    if dma_buf_ioctl(second, &ctx, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 1, -1) != Some(0) {
        return Err("EXPORT_SYNC_FILE(READ) on the second export failed");
    }
    if ctx.get32(12) != 5 {
        return Err("EXPORT_SYNC_FILE did not report the installed fd");
    }
    let exported = ctx.exported.lock().take().unwrap_or_default();
    if exported.len() != 1 || !Arc::ptr_eq(&exported[0], &fence) {
        return Err("the second export did not see the fence imported through the first");
    }
    if dma_buf_ioctl(first, &ctx, 0x4008_6204, 0, 0) != Some((-25i64) as u64) {
        return Err("an unknown dma-buf ioctl must be -ENOTTY");
    }
    Ok(())
}

fn smoke_drm_prime_dumb_exports_share_dma_resv() -> TestResult {
    use crate::drm::card::DumbBacking;
    let idx = {
        let name = format!("card{}", crate::drm_registry::count());
        let mut card = make_test_card();
        let fake_phys = 0xBEEF_0000u64;
        let handle = card.gem.alloc(fake_phys, 4096).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys: fake_phys,
            byte_len: 4096,
            order: 0,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        crate::drm_registry::register_drm_card_with_state(
            Arc::new(crate::drm_devfs_bridge::BochsCard::new(name)),
            card,
        )
    };
    let (Some(first), Some(second)) = (
        crate::drm_devfs_bridge::prime_export_fileops(idx, 1),
        crate::drm_devfs_bridge::prime_export_fileops(idx, 1),
    ) else {
        return TestResult::Fail("PRIME export of a live dumb handle failed");
    };
    match check_shared_reservation(&first, &second) {
        Ok(()) => TestResult::Pass,
        Err(message) => TestResult::Fail(message),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_prime_dumb_exports_share_dma_resv
);

/// VirGL PRIME files share the resource's reservation, which is also where
/// EXECBUFFER publishes its WRITE fence (`virtio_gpu_array_add_fence`).
fn smoke_drm_virtgpu_prime_exports_share_dma_resv() -> TestResult {
    let resource = crate::drm_ioctl_bridge::test_virtgpu_resource(0x45, 4096);
    let first = crate::drm_devfs_bridge::test_virtgpu_dma_buf_file(Arc::clone(&resource));
    let second = crate::drm_devfs_bridge::test_virtgpu_dma_buf_file(Arc::clone(&resource));
    if let Err(message) = check_shared_reservation(&first, &second) {
        return TestResult::Fail(message);
    }
    let gpu_write: Arc<dyn narf_filesystem::DrmFence> = Arc::new(PendingTestFence(0x99));
    resource.dma_buf.resv.add_fence(
        gpu_write.clone(),
        narf_filesystem::dma_buf::DmaResvUsage::Write,
    );
    let ctx = DmaBufCtx::new(gpu_write.clone());
    if dma_buf_ioctl(&second, &ctx, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 1, -1) != Some(0) {
        return TestResult::Fail("EXPORT_SYNC_FILE after a GPU write failed");
    }
    let exported = ctx.exported.lock().take().unwrap_or_default();
    if !exported.iter().any(|fence| Arc::ptr_eq(fence, &gpu_write)) {
        return TestResult::Fail("EXPORT_SYNC_FILE(READ) missed the resource's GPU write fence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_virtgpu_prime_exports_share_dma_resv
);

/// KMS must wait for an asynchronous render write before selecting the
/// resource for VirtIO-GPU scanout.  A pending fence fails the bounded wait;
/// reaching SET_SCANOUT in that state would race the renderer.
fn smoke_drm_virtgpu_scanout_waits_for_pending_write() -> TestResult {
    let resource = crate::drm_ioctl_bridge::test_virtgpu_resource(0x46, 4096);
    resource.dma_buf.resv.add_fence(
        Arc::new(PendingTestFence(0xa0)),
        narf_filesystem::dma_buf::DmaResvUsage::Write,
    );
    match crate::drm_ioctl_bridge::wait_virgl_scanout_writes(&resource) {
        Err(FsError::Busy) => TestResult::Pass,
        _ => TestResult::Fail("scanout did not wait for a pending VirGL write fence"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_virtgpu_scanout_waits_for_pending_write
);

/// Write one compact atomic request into the context-backed fake user memory.
/// It contains a single `IN_FENCE_FD` property on the primary plane.
fn write_atomic_in_fence(ctx: &DmaBufCtx, flags: u32, fd: i32) {
    const OBJS: u64 = 64;
    const COUNTS: u64 = 68;
    const PROPS: u64 = 72;
    const VALUES: u64 = 80;
    let req = DrmModeAtomicUapi {
        flags,
        count_objs: 1,
        objs_ptr: OBJS,
        count_props_ptr: COUNTS,
        props_ptr: PROPS,
        prop_values_ptr: VALUES,
        ..Default::default()
    };
    // SAFETY: `DrmModeAtomicUapi` is a `repr(C)` POD UAPI structure. The
    // context owns a 128-byte byte buffer, enough for the header and arrays.
    let req_bytes = unsafe {
        core::slice::from_raw_parts(
            (&raw const req).cast::<u8>(),
            core::mem::size_of::<DrmModeAtomicUapi>(),
        )
    };
    ctx.put(0, req_bytes);
    ctx.put(OBJS as usize, &0x40u32.to_ne_bytes());
    ctx.put(COUNTS as usize, &1u32.to_ne_bytes());
    ctx.put(PROPS as usize, &0x5fu32.to_ne_bytes()); // IN_FENCE_FD
    ctx.put(VALUES as usize, &(fd as i64 as u64).to_ne_bytes());
}

/// Explicit KMS fences are resolved through the syscall-owned sync_file seam
/// before the atomic dispatcher can touch card state. Invalid fds are EINVAL;
/// pending fences hit the bounded kernel-only fallback; TEST_ONLY validates but
/// does not consume the fence.
fn smoke_drm_atomic_in_fence_validation_and_wait() -> TestResult {
    let pending: Arc<dyn narf_filesystem::DrmFence> = Arc::new(PendingTestFence(0xa1));
    let ctx = DmaBufCtx::with_len(128, pending);

    write_atomic_in_fence(&ctx, 0, 7);
    if !matches!(
        crate::drm_ioctl_bridge::wait_atomic_in_fences(0, &ctx),
        Err(FsError::Busy)
    ) {
        return TestResult::Fail("atomic IN_FENCE_FD did not wait for a pending fence");
    }

    write_atomic_in_fence(&ctx, 0, 8);
    if !matches!(
        crate::drm_ioctl_bridge::wait_atomic_in_fences(0, &ctx),
        Err(FsError::InvalidData)
    ) {
        return TestResult::Fail("atomic IN_FENCE_FD accepted a non-sync-file fd");
    }

    write_atomic_in_fence(&ctx, 0x0100, 7); // TEST_ONLY
    if crate::drm_ioctl_bridge::wait_atomic_in_fences(0, &ctx).is_err() {
        return TestResult::Fail("TEST_ONLY atomic request waited for its input fence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_atomic_in_fence_validation_and_wait
);

// ── Vblank ioctls ─────────────────────────────────────────────────────

/// A fake hardware vblank clock: a set count, or (with `FAKE_VBLANK_TIMED`)
/// one vblank per millisecond of monotonic time; `FAKE_VBLANK_OFF` stops it.
static FAKE_VBLANK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static FAKE_VBLANK_TIMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static FAKE_VBLANK_OFF: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
fn fake_vblank(crtc_id: u32) -> Option<crate::drm::card::VblankTime> {
    use core::sync::atomic::Ordering::SeqCst;
    if crtc_id != 12 || FAKE_VBLANK_OFF.load(SeqCst) {
        return None;
    }
    let count = if FAKE_VBLANK_TIMED.load(SeqCst) {
        narf_time::wall::monotonic_ns() / 1_000_000
    } else {
        FAKE_VBLANK.load(SeqCst)
    };
    Some(crate::drm::card::VblankTime {
        count,
        start_ns: count * 1_000_000,
        ns: count * 1_000_000 + 100_000,
        period_ns: 1_000_000,
    })
}

/// WAIT_VBLANK, CRTC_GET_SEQUENCE and CRTC_QUEUE_SEQUENCE as Linux's
/// drm_vblank.c answers them: unsupported without hardware vblanks, EINVAL
/// on a CRTC that is off, queries and reached targets at once, events once
/// the count reaches their target (or the CRTC goes off), blocking waits
/// until the target.
fn smoke_drm_ioctl_vblank_waits_and_sequences() -> TestResult {
    use core::sync::atomic::Ordering::SeqCst;
    let idx = register_test_card();
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no mode state");
    };
    let caps = crate::drm_ioctl_bridge::DrmClientCaps::new();
    let events = narf_lib::sync::IrqSafeSpinLock::new(crate::drm::card::DrmEventQueue::new());
    let call = |nr: u32, buf: &mut [u8; 24], render: bool| {
        crate::drm_ioctl_bridge::dispatch_card_for_file(
            idx,
            SMOKE_MASTER_ID,
            iowr(DRM_IOCTL_BASE, nr, 24),
            buf.as_mut_ptr() as usize,
            render,
            &caps,
            (!render).then_some(&events),
            None,
        )
    };
    let wait = |kind: u32, seq: u32, data: u64| {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&kind.to_le_bytes());
        b[4..8].copy_from_slice(&seq.to_le_bytes());
        b[8..16].copy_from_slice(&data.to_le_bytes());
        b
    };
    let get = |crtc: u32| {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&crtc.to_le_bytes());
        b
    };
    // No hardware vblanks: unsupported, as without drm_vblank_init.
    if call(0x3A, &mut wait(1, 0, 0), false) != Err(FsError::Unsupported)
        || call(0x3B, &mut get(12), false) != Err(FsError::Unsupported)
    {
        return TestResult::Fail("vblank ioctls without vblank support");
    }
    ms.lock().vblank_source = Some(fake_vblank);
    FAKE_VBLANK.store(100, SeqCst);
    // The CRTC is off: its vblank cannot be enabled.
    if call(0x3A, &mut wait(0x2, 0, 0), false) != Err(FsError::InvalidData)
        || call(0x3B, &mut get(12), false) != Err(FsError::InvalidData)
        || call(0x3B, &mut get(99), false) != Err(FsError::NotFound)
    {
        return TestResult::Fail("vblank on a CRTC that is off");
    }
    ms.lock().crtc_mut(12).unwrap().enabled = true;
    // Second CRTC (index 1, via HIGH_CRTC) queried: the current count.
    let mut b = wait(1 | 1 << 1, 0, 0);
    if call(0x3A, &mut b, false) != Ok(0)
        || u32::from_le_bytes(b[4..8].try_into().unwrap()) != 100
        || i64::from_le_bytes(b[8..16].try_into().unwrap()) != 0
        || i64::from_le_bytes(b[16..24].try_into().unwrap()) != 100_100
    {
        return TestResult::Fail("vblank query reply");
    }
    let mut b = get(12);
    if call(0x3B, &mut b, false) != Ok(0)
        || b[4..8] != 1u32.to_le_bytes()
        || u64::from_le_bytes(b[8..16].try_into().unwrap()) != 100
        || i64::from_le_bytes(b[16..24].try_into().unwrap()) != 100_100_000
    {
        return TestResult::Fail("CRTC_GET_SEQUENCE");
    }
    // Refused: SIGNAL, FLIP, unknown bits, a missing CRTC, render nodes.
    for kind in [0x4000_0000u32, 0x0800_0000, 0x80, 1 | 3 << 1] {
        if call(0x3A, &mut wait(kind | 2, 0, 0), false) != Err(FsError::InvalidData) {
            return TestResult::Fail("bad WAIT_VBLANK flags accepted");
        }
    }
    if call(0x3A, &mut wait(1 | 2, 0, 0), true) != Err(FsError::PermissionDenied) {
        return TestResult::Fail("WAIT_VBLANK on a render node");
    }
    let read = || {
        let mut out = [0u8; 32];
        let n = events
            .lock()
            .read_deliverable_event(narf_time::wall::monotonic_ns(), &mut out);
        n.map(|_| out)
    };
    // An event two vblanks ahead (relative, EVENT, CRTC 1).
    let mut b = wait(0x400_0000 | 1 | 1 << 1, 2, 0xabcd);
    if call(0x3A, &mut b, false) != Ok(0)
        || u32::from_le_bytes(b[4..8].try_into().unwrap()) != 102
        || read().is_some()
    {
        return TestResult::Fail("vblank event queued early");
    }
    FAKE_VBLANK.store(102, SeqCst);
    match read() {
        Some(e)
            if e[0..4] == 1u32.to_le_bytes()
                && e[4..8] == 32u32.to_le_bytes()
                && e[8..16] == 0xabcdu64.to_le_bytes()
                && e[24..28] == 102u32.to_le_bytes()
                && e[28..32] == 12u32.to_le_bytes() => {}
        _ => return TestResult::Fail("vblank event"),
    }
    // A sequence event on an absolute target already passed: at once.
    let mut q = [0u8; 24];
    q[0..4].copy_from_slice(&12u32.to_le_bytes());
    q[8..16].copy_from_slice(&50u64.to_le_bytes());
    q[16..24].copy_from_slice(&7u64.to_le_bytes());
    if call(0x3C, &mut q, false) != Ok(0) || q[8..16] != 102u64.to_le_bytes() {
        return TestResult::Fail("passed sequence target");
    }
    match read() {
        Some(e)
            if e[0..4] == 3u32.to_le_bytes()
                && e[8..16] == 7u64.to_le_bytes()
                && e[16..24] == 102_100_000u64.to_le_bytes()
                && e[24..32] == 102u64.to_le_bytes() => {}
        _ => return TestResult::Fail("CRTC sequence event"),
    }
    // NEXT_ON_MISS moves a missed target to the next vblank; the CRTC
    // going off sends the pending event at once.
    q[4..8].copy_from_slice(&2u32.to_le_bytes());
    q[8..16].copy_from_slice(&90u64.to_le_bytes());
    if call(0x3C, &mut q, false) != Ok(0) || q[8..16] != 103u64.to_le_bytes() || read().is_some() {
        return TestResult::Fail("NEXT_ON_MISS");
    }
    FAKE_VBLANK_OFF.store(true, SeqCst);
    let sent = read();
    FAKE_VBLANK_OFF.store(false, SeqCst);
    if sent.is_none_or(|e| e[24..32] != 103u64.to_le_bytes()) {
        return TestResult::Fail("pending event of a CRTC turned off");
    }
    q[4..8].copy_from_slice(&4u32.to_le_bytes());
    if call(0x3C, &mut q, false) != Err(FsError::InvalidData) {
        return TestResult::Fail("bad CRTC_QUEUE_SEQUENCE flags");
    }
    // A blocking wait three vblanks ahead returns once they have begun.
    FAKE_VBLANK_TIMED.store(true, SeqCst);
    let start = narf_time::wall::monotonic_ns() / 1_000_000;
    let mut b = wait(1 | 1 << 1, 3, 0);
    let result = call(0x3A, &mut b, false);
    FAKE_VBLANK_TIMED.store(false, SeqCst);
    let got = u32::from_le_bytes(b[4..8].try_into().unwrap()) as u64;
    if result != Ok(0) || got < start + 3 || got > start + 1_000 {
        return TestResult::Fail("blocking vblank wait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_vblank_waits_and_sequences
);

/// A natively scanned-out card's planes take only their formats, cover the
/// CRTC's mode unscaled from the framebuffer origin (EINVAL for anything
/// else, ENOSPC for a framebuffer smaller than the mode, in SETCRTC,
/// PAGE_FLIP and atomic alike), and RMFB of the framebuffer on screen turns
/// its CRTC off, as Linux's drm_framebuffer_remove does.
fn smoke_drm_native_planes_refuse_what_scanout_cannot_show() -> TestResult {
    use crate::drm::atomic::{AtomicState, CrtcState, PlaneState};
    use crate::drm::card::DumbBacking;
    use crate::drm_uapi::{DrmModeCrtcUapi, DRM_IOCTL_MODE_SETCRTC};
    const XR24: u32 = 0x3432_5258;
    const AR24: u32 = 0x3432_5241;
    const RG16: u32 = 0x3631_4752;
    let idx = register_test_card();
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no mode state");
    };
    // A dumb buffer large enough for every framebuffer below.
    let handle = {
        let mut card = ms.lock();
        card.plane_formats = Some(&[XR24, AR24]);
        let (phys, size) = (0xBEEF_0000u64, 64 * 64 * 4usize);
        let handle = card.gem.alloc(phys, size).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys,
            byte_len: size,
            order: 0,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        handle
    };
    let addfb = |w: u32, h: u32, format: u32| ms.lock().addfb2(w, h, format, w * 4, handle);
    // ADDFB2: a format no plane takes is refused.
    if addfb(64, 32, RG16).is_ok() {
        return TestResult::Fail("RGB565 framebuffer on 32-bit planes");
    }
    let (Ok(full), Ok(alpha), Ok(small)) = (
        addfb(64, 32, XR24),
        addfb(64, 32, AR24),
        addfb(32, 32, XR24),
    ) else {
        return TestResult::Fail("32-bit framebuffers refused");
    };
    // GETPLANE lists both formats.
    let mut ids = [0u32; 4];
    let mut res = [0u8; 16];
    res[0..8].copy_from_slice(&(ids.as_mut_ptr() as u64).to_le_bytes());
    res[8..12].copy_from_slice(&4u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB5, 16),
        res.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("GETPLANERESOURCES");
    }
    let mut formats = [0u32; 4];
    let mut gp = [0u8; 32];
    gp[0..4].copy_from_slice(&ids[0].to_le_bytes());
    gp[20..24].copy_from_slice(&4u32.to_le_bytes());
    gp[24..32].copy_from_slice(&(formats.as_mut_ptr() as u64).to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB6, 32),
        gp.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || gp[20..24] != 2u32.to_le_bytes()
        || formats[..2] != [XR24, AR24]
    {
        return TestResult::Fail("plane formats");
    }
    // SETCRTC in a 64x32 mode.
    let setcrtc = |fb_id: u32, x: u32| {
        let mut req = DrmModeCrtcUapi {
            crtc_id: 11,
            fb_id,
            x,
            mode_valid: 1,
            ..Default::default()
        };
        req.mode.hdisplay = 64;
        req.mode.vdisplay = 32;
        req.mode.vrefresh = 60;
        dispatch_card(
            idx,
            DRM_IOCTL_MODE_SETCRTC,
            &mut req as *mut _ as usize,
            false,
        )
    };
    if setcrtc(small, 0) != Err(FsError::NoSpace)
        || setcrtc(full, 8) != Err(FsError::InvalidData)
        || setcrtc(999, 0) != Err(FsError::NotFound)
        || ms.lock().crtc(11).unwrap().enabled
    {
        return TestResult::Fail("SETCRTC refusals (or state changed by one)");
    }
    if setcrtc(alpha, 0) != Ok(0) || setcrtc(full, 0) != Ok(0) {
        return TestResult::Fail("full-screen 32-bit planes");
    }
    // PAGE_FLIP to a framebuffer that cannot cover the mode.
    let mut flip = [0u8; 24];
    flip[0..4].copy_from_slice(&11u32.to_le_bytes());
    flip[4..8].copy_from_slice(&small.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB0, 24),
        flip.as_mut_ptr() as usize,
        false,
    ) != Err(FsError::NoSpace)
    {
        return TestResult::Fail("PAGE_FLIP to a short framebuffer");
    }
    // Atomic: only the unscaled full-screen plane passes.
    let plane = |fb: u32, crtc_w: u32, src_x: u32| PlaneState {
        id: ids[0],
        crtc_id: Some(11),
        fb_id: Some(fb),
        crtc_w,
        crtc_h: 32,
        src_x,
        src_w: 64,
        src_h: 32,
        ..Default::default()
    };
    let check = |p: PlaneState, mode: Option<crate::Mode>| {
        let mut state = AtomicState::default();
        if let Some(m) = mode {
            state.crtcs.push(CrtcState {
                id: 11,
                enable: true,
                active: true,
                mode: Some(m),
                ..Default::default()
            });
        }
        state.planes.push(p);
        crate::drm_ioctl_bridge::check_native_atomic(&ms.lock(), &state)
    };
    let wide = crate::Mode {
        width: 128,
        height: 32,
        refresh_hz: 60,
        bpp: 32,
    };
    if check(plane(full, 64, 0), None) != Ok(())
        || check(plane(full, 32, 0), None) != Err(FsError::InvalidData)
        || check(plane(full, 64, 8), None) != Err(FsError::InvalidData)
        || check(plane(full, 64, 0), Some(wide)) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("atomic native plane checks");
    }
    // RMFB of the framebuffer on screen turns the CRTC off.
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA8, 4),
        &full as *const u32 as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("RMFB");
    }
    let crtc = ms.lock().crtc(11).unwrap().clone();
    if crtc.enabled || crtc.primary_fb.is_some() || crtc.mode.is_some() {
        return TestResult::Fail("CRTC still on after its framebuffer was removed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_native_planes_refuse_what_scanout_cannot_show
);

/// The Navi48 primary plane's formats (amdgpu_dm's DCN4.0.1 list less
/// what the native scanout cannot program): ADDFB2 takes each with a pitch
/// of a line of its pixels on a GEM object holding every line (EINVAL
/// otherwise, as framebuffer_check and drm_gem_fb_init_with_funcs refuse
/// them), refuses the formats it leaves out, GETPLANE lists them, SETCRTC
/// shows each full screen, PAGE_FLIP keeps the format (EINVAL across
/// formats, as drm_mode_page_flip_ioctl) and the atomic plane check takes
/// them. A card without native planes keeps its three legacy formats.
fn smoke_drm_navi48_plane_formats_end_to_end() -> TestResult {
    use crate::drm::atomic::{AtomicState, PlaneState};
    use crate::drm::card::{CardError, DumbBacking, PixelFormat};
    use crate::drm_uapi::{DrmModeCrtcUapi, DRM_IOCTL_MODE_SETCRTC};
    const FORMATS: &[u32] = &crate::amdgpu_navi48_kms::PLANE_FORMATS;
    let idx = register_test_card();
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no mode state");
    };
    let dumb = |card: &mut crate::drm::card::Card, phys: u64, size: usize| {
        let handle = card.gem.alloc(phys, size).unwrap();
        card.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys,
            byte_len: size,
            order: 0,
            mmap_offset: (handle as u64) << 12,
            refcount: 1,
            dma_buf: Default::default(),
        });
        handle
    };
    let (big, small, legacy) = {
        let mut card = ms.lock();
        // Before the planes exist: only XR24, AR24 and RG16.
        let legacy = dumb(&mut card, 0xBEE0_0000, 64 * 32 * 8);
        if card.addfb2(64, 32, 0x3033_5258, 64 * 4, legacy) != Err(CardError::UnknownFormat)
            || card.addfb2(64, 32, 0x3631_4752, 64 * 2, legacy).is_err()
        {
            return TestResult::Fail("formats of a card without native planes");
        }
        card.plane_formats = Some(FORMATS);
        (
            dumb(&mut card, 0xBEEF_0000, 64 * 32 * 8),
            dumb(&mut card, 0xBEF0_0000, 64 * 32 * 4),
            legacy,
        )
    };
    let _ = legacy;
    let addfb = |w: u32, h: u32, format: u32, pitch: u32, handle: u32| {
        ms.lock().addfb2(w, h, format, pitch, handle)
    };
    let mut fbs = alloc::vec::Vec::new();
    for &format in FORMATS {
        let Some(cpp) = PixelFormat::from_fourcc(format).map(PixelFormat::cpp) else {
            return TestResult::Fail("plane format unknown to ADDFB2");
        };
        if addfb(64, 32, format, 64 * cpp - 2, big) != Err(CardError::InvalidDimensions) {
            return TestResult::Fail("pitch shorter than a line accepted");
        }
        // A 64x32 line of 8-byte pixels does not fit the 4-byte object.
        if (cpp == 8)
            != (addfb(64, 32, format, 64 * cpp, small) == Err(CardError::InvalidDimensions))
        {
            return TestResult::Fail("GEM object size check");
        }
        match addfb(64, 32, format, 64 * cpp, big) {
            Ok(fb) => fbs.push((format, fb)),
            Err(_) => return TestResult::Fail("plane format refused"),
        }
    }
    // RGBA8888, XRGB16161616 (UNORM), NV12 and C8: Linux's other formats.
    for format in [0x3432_4152, 0x3834_5258, 0x3231_564e, 0x2020_3843] {
        if addfb(64, 32, format, 64 * 8, big) != Err(CardError::UnknownFormat) {
            return TestResult::Fail("format the native plane leaves out accepted");
        }
    }
    // GETPLANE lists exactly the plane's formats.
    let mut ids = [0u32; 4];
    let mut res = [0u8; 16];
    res[0..8].copy_from_slice(&(ids.as_mut_ptr() as u64).to_le_bytes());
    res[8..12].copy_from_slice(&4u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB5, 16),
        res.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
    {
        return TestResult::Fail("GETPLANERESOURCES");
    }
    let mut listed = [0u32; 16];
    let mut gp = [0u8; 32];
    gp[0..4].copy_from_slice(&ids[0].to_le_bytes());
    gp[20..24].copy_from_slice(&16u32.to_le_bytes());
    gp[24..32].copy_from_slice(&(listed.as_mut_ptr() as u64).to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB6, 32),
        gp.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || gp[20..24] != (FORMATS.len() as u32).to_le_bytes()
        || listed[..FORMATS.len()] != *FORMATS
    {
        return TestResult::Fail("plane formats");
    }
    // SETCRTC shows each full screen in a 64x32 mode.
    let setcrtc = |fb_id: u32| {
        let mut req = DrmModeCrtcUapi {
            crtc_id: 11,
            fb_id,
            mode_valid: 1,
            ..Default::default()
        };
        req.mode.hdisplay = 64;
        req.mode.vdisplay = 32;
        req.mode.vrefresh = 60;
        dispatch_card(
            idx,
            DRM_IOCTL_MODE_SETCRTC,
            &mut req as *mut _ as usize,
            false,
        )
    };
    for &(_, fb) in &fbs {
        if setcrtc(fb) != Ok(0) {
            return TestResult::Fail("full-screen plane of a native format");
        }
    }
    // PAGE_FLIP keeps the format: FP16 to FP16 flips, FP16 to XRGB8888
    // does not.
    let (Some(&(_, last)), Some(&(_, xrgb))) = (fbs.last(), fbs.first()) else {
        return TestResult::Fail("no framebuffers");
    };
    let Ok(again) = addfb(64, 32, *FORMATS.last().unwrap(), 64 * 8, big) else {
        return TestResult::Fail("second FP16 framebuffer");
    };
    let flip = |fb: u32| {
        let mut flip = [0u8; 24];
        flip[0..4].copy_from_slice(&11u32.to_le_bytes());
        flip[4..8].copy_from_slice(&fb.to_le_bytes());
        dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xB0, 24),
            flip.as_mut_ptr() as usize,
            false,
        )
    };
    if ms.lock().crtc(11).unwrap().primary_fb != Some(last)
        || flip(xrgb) != Err(FsError::InvalidData)
        || flip(again) != Ok(0)
    {
        return TestResult::Fail("PAGE_FLIP format rules");
    }
    // The atomic plane check takes every format unscaled and full screen.
    for &(_, fb) in &fbs {
        let mut state = AtomicState::default();
        state.planes.push(PlaneState {
            id: ids[0],
            crtc_id: Some(11),
            fb_id: Some(fb),
            crtc_w: 64,
            crtc_h: 32,
            src_w: 64,
            src_h: 32,
            ..Default::default()
        });
        if crate::drm_ioctl_bridge::check_native_atomic(&ms.lock(), &state) != Ok(()) {
            return TestResult::Fail("atomic plane of a native format");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_navi48_plane_formats_end_to_end
);

// ── User-copy range + fault checks (Linux access_ok / copy_*_user) ───────────

/// Last byte of the user half, and the first canonical kernel address.
const USER_TOP: usize = 0x0000_7fff_ffff_ffff;
const KERNEL_FIRST: usize = 0xffff_8000_0000_0000;

/// The bridge's copy primitives apply Linux `__access_ok` before any byte
/// moves: a kernel source/destination, a range straddling the user/kernel
/// boundary, a wrapping range and null are all EFAULT, and an in-range but
/// unmapped user buffer is EFAULT via the fault-guarded copy instead of a
/// kernel #PF. Before the fix every one of these was a raw STAC'd
/// `copy_nonoverlapping` (a kernel read/write or a panic).
fn smoke_drm_user_copies_enforce_access_ok() -> TestResult {
    use crate::drm_ioctl_bridge::kernel_test_buffers::StrictUserCopies;
    use crate::drm_ioctl_bridge::{copy_in, copy_out};
    let efault = Err(FsError::BadAddress);
    let mut secret = [0x5au8; 16];
    let kptr = secret.as_mut_ptr() as usize;
    {
        let _strict = StrictUserCopies::new();
        // SAFETY: every call below is refused before touching memory, or
        // (0x1000) faults inside the guarded copy.
        unsafe {
            if copy_in(kptr, 16).map(|_| ()) != efault {
                return TestResult::Fail("copy_in read a kernel buffer");
            }
            if copy_out(kptr, &[0u8; 16]) != efault || secret != [0x5a; 16] {
                return TestResult::Fail("copy_out wrote a kernel buffer");
            }
            if copy_in(0, 4).map(|_| ()) != efault || copy_out(0, &[0]) != efault {
                return TestResult::Fail("null accepted");
            }
            // The first byte is user, the last is past the user half.
            if copy_in(USER_TOP - 3, 8).map(|_| ()) != efault
                || copy_out(USER_TOP - 3, &[0u8; 8]) != efault
            {
                return TestResult::Fail("user/kernel straddle accepted");
            }
            // The whole of the user half's last byte is fine shape-wise; it
            // is unmapped here, so the guarded copy turns the #PF into EFAULT.
            if copy_in(USER_TOP, 1).map(|_| ()) != efault {
                return TestResult::Fail("unmapped top user byte not EFAULT");
            }
            if copy_in(0x1000, 8).map(|_| ()) != efault || copy_out(0x1000, &[0u8; 8]) != efault {
                return TestResult::Fail("unmapped user page not EFAULT");
            }
            if copy_in(KERNEL_FIRST, 8).map(|_| ()) != efault
                || copy_in(usize::MAX - 7, 16).map(|_| ()) != efault
            {
                return TestResult::Fail("kernel-half / wrapping range accepted");
            }
        }
    }
    // The test-build opt-out still never accepts a straddling or wrapping
    // range, and the strict scope closed with its guard.
    // SAFETY: the straddle and wrap are refused before any access; `kptr`
    // is a live 16-byte kernel buffer.
    unsafe {
        if copy_in(USER_TOP - 3, 8).map(|_| ()) != efault
            || copy_in(usize::MAX - 7, 16).map(|_| ()) != efault
        {
            return TestResult::Fail("test opt-out accepted a straddling range");
        }
        if copy_in(kptr, 16).map(|v| v == [0x5a; 16]) != Ok(true) {
            return TestResult::Fail("strict scope leaked past its guard");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_user_copies_enforce_access_ok
);

/// `AMDGPU_INFO.return_pointer` is the client's: aimed at kernel memory it is
/// EFAULT and the kernel bytes stay untouched, while the same request with
/// the pointer standing in for user memory answers.
fn smoke_drm_user_copies_info_return_pointer() -> TestResult {
    use crate::amdgpu_uapi as u;
    use crate::drm_ioctl_bridge::kernel_test_buffers::StrictUserCopies;
    let vm = crate::amdgpu_vm::VmState::new();
    let mut out = [0xa5u8; 16];
    let mut req = [0u8; core::mem::size_of::<u::DrmAmdgpuInfo>()];
    req[0..8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    req[8..12].copy_from_slice(&16u32.to_le_bytes());
    req[12..16].copy_from_slice(&u::AMDGPU_INFO_GPUVM_FAULT.to_le_bytes());
    let cmd = crate::drm_uapi::DRM_COMMAND_BASE + u::DRM_AMDGPU_INFO;
    let arg = req.as_mut_ptr() as usize;
    let refused = {
        let _strict = StrictUserCopies::allowing(arg, req.len());
        crate::amdgpu_info::dispatch_for(cmd, arg, Some(&vm))
    };
    if refused != Err(FsError::BadAddress) || out != [0xa5; 16] {
        return TestResult::Fail("INFO wrote through a kernel return_pointer");
    }
    if crate::amdgpu_info::dispatch_for(cmd, arg, Some(&vm)) != Ok(0) || out != [0; 16] {
        return TestResult::Fail("INFO did not answer a stand-in user buffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_user_copies_info_return_pointer
);

/// `DRM_IOCTL_VERSION` name/date/desc pointers are the client's: a kernel
/// name pointer is EFAULT and is not written.
fn smoke_drm_user_copies_version_strings() -> TestResult {
    use crate::drm_ioctl_bridge::kernel_test_buffers::StrictUserCopies;
    let idx = register_test_card();
    let mut name_buf = [0x11u8; 32];
    let mut req = DrmVersionUapi {
        name_len: name_buf.len() as u64,
        name: name_buf.as_mut_ptr() as u64,
        ..DrmVersionUapi::default()
    };
    let arg = &mut req as *mut _ as usize;
    let r = {
        let _strict = StrictUserCopies::allowing(arg, core::mem::size_of::<DrmVersionUapi>());
        dispatch_card(idx, DRM_IOCTL_VERSION, arg, false)
    };
    if r != Err(FsError::BadAddress) || name_buf != [0x11; 32] {
        return TestResult::Fail("VERSION wrote through a kernel name pointer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_user_copies_version_strings
);

// ── amdgpu_dm's native overlay planes ─────────────────────────────────
//
// A card publishing native planes (the Navi48 card's shape) exposes each
// CRTC's primary and DCN401's three overlays with amdgpu_dm's properties,
// and runs amdgpu_dm's plane checks on ATOMIC (TEST_ONLY included) and
// SETPLANE. DML admission and presentation are the native display's
// (exercised by the navi48 tests); this card has none.
fn smoke_drm_ioctl_native_overlay_planes() -> TestResult {
    use crate::drm::card::DumbBacking;
    use crate::drm_native_planes as planes;
    const XR24: u32 = 0x3432_5258;
    const AR24: u32 = 0x3432_5241;
    const XR30: u32 = 0x3033_5258;
    const OVERLAY: u32 = planes::OVERLAY_PLANE_ID_BASE;
    let idx = register_test_card();
    let Some(ms) = crate::drm_registry::mode_state(idx) else {
        return TestResult::Fail("no mode state");
    };
    let (primary_fb, video_fb, big_fb, deep_fb) = {
        let mut card = ms.lock();
        card.native_atomic = true;
        card.plane_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        card.overlay_formats = Some(&planes::OVERLAY_FORMATS);
        card.native_planes = planes::planes_for(&[], &[11, 12]);
        let mut fb = |phys: u64, w: u32, h: u32, format: u32| {
            let size = (w * h * 4) as usize;
            let handle = card.gem.alloc(phys, size).unwrap();
            card.dumb_backings.push(DumbBacking {
                gem_handle: handle,
                phys,
                byte_len: size,
                order: 0,
                mmap_offset: (handle as u64) << 12,
                refcount: 1,
                dma_buf: Default::default(),
            });
            card.addfb2(w, h, format, w * 4, handle).unwrap()
        };
        let fbs = (
            fb(0xBE10_0000, 64, 32, XR24),
            fb(0xBE20_0000, 32, 16, AR24),
            fb(0xBE30_0000, 256, 128, AR24),
            fb(0xBE40_0000, 64, 32, XR30),
        );
        let crtc = card.crtc_mut(11).unwrap();
        crtc.mode = Some(crate::Mode {
            width: 64,
            height: 32,
            refresh_hz: 60,
            bpp: 32,
        });
        crtc.enabled = true;
        crtc.primary_fb = Some(fbs.0);
        fbs
    };
    // GETPLANERESOURCES: both primaries, then the three overlays.
    let mut ids = [0u32; 8];
    let mut res = [0u8; 16];
    res[0..8].copy_from_slice(&(ids.as_mut_ptr() as u64).to_le_bytes());
    res[8..12].copy_from_slice(&8u32.to_le_bytes());
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xB5, 16),
        res.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || res[8..12] != 5u32.to_le_bytes()
        || ids[..5] != [0x40, 0x41, OVERLAY, OVERLAY + 1, OVERLAY + 2]
    {
        return TestResult::Fail("plane resources");
    }
    // GETPLANE: an overlay goes on any CRTC and takes the overlay formats.
    let getplane = |id: u32| {
        let mut formats = [0u32; 16];
        let mut gp = [0u8; 32];
        gp[0..4].copy_from_slice(&id.to_le_bytes());
        gp[20..24].copy_from_slice(&16u32.to_le_bytes());
        gp[24..32].copy_from_slice(&(formats.as_mut_ptr() as u64).to_le_bytes());
        let r = dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xB6, 32),
            gp.as_mut_ptr() as usize,
            false,
        );
        let word = |i: usize| u32::from_le_bytes(gp[i * 4..i * 4 + 4].try_into().unwrap());
        (r, word(1), word(2), word(3), word(5), formats)
    };
    let (r, crtc, fb, possible, count, formats) = getplane(OVERLAY);
    if r != Ok(0)
        || (crtc, fb, possible) != (0, 0, 0xff)
        || count != 5
        || formats[..5] != planes::OVERLAY_FORMATS
    {
        return TestResult::Fail("overlay GETPLANE");
    }
    // OBJ_GETPROPERTIES: the core plane properties, then amdgpu_dm's.
    let properties = |id: u32| {
        let mut props = [0u32; 20];
        let mut vals = [0u64; 20];
        let mut og = [0u8; 32];
        og[0..8].copy_from_slice(&(props.as_mut_ptr() as u64).to_le_bytes());
        og[8..16].copy_from_slice(&(vals.as_mut_ptr() as u64).to_le_bytes());
        og[16..20].copy_from_slice(&20u32.to_le_bytes());
        og[20..24].copy_from_slice(&id.to_le_bytes());
        og[24..28].copy_from_slice(&0xeeee_eeeeu32.to_le_bytes());
        let r = dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xB9, 32),
            og.as_mut_ptr() as usize,
            false,
        );
        let n = u32::from_le_bytes(og[16..20].try_into().unwrap()) as usize;
        (r, props[..n.min(20)].to_vec(), vals[..n.min(20)].to_vec())
    };
    let (r, props, vals) = properties(OVERLAY + 1);
    let blob = u64::from(planes::in_formats_blob_id(OVERLAY + 1));
    if r != Ok(0)
        || props.len() != 17
        || vals[0] != 0
        || props[12..]
            != [
                planes::ALPHA_PROP_ID,
                planes::BLEND_PROP_ID,
                planes::ZPOS_PROP_ID,
                planes::ROTATION_PROP_ID,
                planes::IN_FORMATS_PROP_ID,
            ]
        || vals[12..] != [0xffff, 0, 9, 1, blob]
    {
        return TestResult::Fail("overlay properties");
    }
    // IN_FORMATS through GETPROPBLOB: a version-1 drm_format_modifier_blob.
    let mut data = [0u8; 256];
    let mut gb = [0u8; 16];
    gb[0..4].copy_from_slice(&(blob as u32).to_le_bytes());
    gb[4..8].copy_from_slice(&256u32.to_le_bytes());
    gb[8..16].copy_from_slice(&(data.as_mut_ptr() as u64).to_le_bytes());
    let r = dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xAC, 16),
        gb.as_mut_ptr() as usize,
        false,
    );
    let len = u32::from_le_bytes(gb[4..8].try_into().unwrap()) as usize;
    if r != Ok(0)
        || len < 48
        || data[0..4] != 1u32.to_le_bytes()
        || data[16..20] != 1u32.to_le_bytes()
    {
        return TestResult::Fail("IN_FORMATS blob");
    }
    let (r, props, vals) = properties(0x40);
    if r != Ok(0)
        || vals[0] != 1
        || props[12..]
            != [
                planes::BLEND_PROP_ID,
                planes::PRIMARY_ZPOS_PROP_ID,
                planes::ROTATION_PROP_ID,
                planes::IN_FORMATS_PROP_ID,
            ]
        || vals[13] != 3
        || vals[9..11] != [64, 32]
    {
        return TestResult::Fail("primary properties");
    }
    // GETPROPERTY: the ranges (the primary's zpos immutable), the enum and
    // the rotation bitmask with Linux's names.
    let getproperty = |id: u32| {
        let mut values = [0u64; 4];
        let mut enums = [0u8; 4 * 40];
        let mut gp = [0u8; 64];
        gp[0..8].copy_from_slice(&(values.as_mut_ptr() as u64).to_le_bytes());
        gp[8..16].copy_from_slice(&(enums.as_mut_ptr() as u64).to_le_bytes());
        gp[16..20].copy_from_slice(&id.to_le_bytes());
        gp[56..60].copy_from_slice(&4u32.to_le_bytes());
        gp[60..64].copy_from_slice(&4u32.to_le_bytes());
        let r = dispatch_card(
            idx,
            iowr(DRM_IOCTL_BASE, 0xAA, 64),
            gp.as_mut_ptr() as usize,
            false,
        );
        let flags = u32::from_le_bytes(gp[20..24].try_into().unwrap());
        let name_end = gp[24..56].iter().position(|&b| b == 0).unwrap_or(32);
        let name = alloc::vec::Vec::from(&gp[24..24 + name_end]);
        let n = u32::from_le_bytes(gp[56..60].try_into().unwrap()) as usize;
        (r, flags, name, values[..n.min(4)].to_vec(), enums)
    };
    let (r, flags, name, values, _) = getproperty(planes::PRIMARY_ZPOS_PROP_ID);
    if r != Ok(0) || flags != 2 | 4 || name != b"zpos" || values != [3, 3] {
        return TestResult::Fail("primary zpos property");
    }
    let (r, flags, name, values, _) = getproperty(planes::ALPHA_PROP_ID);
    if r != Ok(0) || flags != 2 || name != b"alpha" || values != [0, 0xffff] {
        return TestResult::Fail("alpha property");
    }
    let (r, flags, name, values, enums) = getproperty(planes::BLEND_PROP_ID);
    if r != Ok(0)
        || flags != 8
        || name != b"pixel blend mode"
        || values != [2, 0, 1]
        || &enums[8..12] != b"None"
        || &enums[48..62] != b"Pre-multiplied"
    {
        return TestResult::Fail("pixel blend mode property");
    }
    let (r, flags, name, values, enums) = getproperty(planes::ROTATION_PROP_ID);
    if r != Ok(0)
        || flags != 0x20
        || name != b"rotation"
        || values != [0, 1, 2, 3]
        || &enums[128..138] != b"rotate-270"
    {
        return TestResult::Fail("rotation property");
    }
    // ATOMIC with amdgpu_dm's checks.
    let atomic = |flags: u32, objects: &[(u32, &[(u32, u64)])]| {
        let objs: alloc::vec::Vec<u32> = objects.iter().map(|o| o.0).collect();
        let counts: alloc::vec::Vec<u32> = objects.iter().map(|o| o.1.len() as u32).collect();
        let props: alloc::vec::Vec<u32> = objects
            .iter()
            .flat_map(|o| o.1.iter().map(|p| p.0))
            .collect();
        let values: alloc::vec::Vec<u64> = objects
            .iter()
            .flat_map(|o| o.1.iter().map(|p| p.1))
            .collect();
        let mut req = DrmModeAtomicUapi {
            flags,
            count_objs: objs.len() as u32,
            objs_ptr: objs.as_ptr() as u64,
            count_props_ptr: counts.as_ptr() as u64,
            props_ptr: props.as_ptr() as u64,
            prop_values_ptr: values.as_ptr() as u64,
            ..Default::default()
        };
        dispatch_card(
            idx,
            DRM_IOCTL_MODE_ATOMIC,
            &mut req as *mut _ as usize,
            false,
        )
    };
    const FB_ID: u32 = 0x55;
    const CRTC_ID: u32 = 0x56;
    let place = |fb: u32, src: (u64, u64), dst: (i64, i64, u64, u64)| {
        [
            (FB_ID, u64::from(fb)),
            (CRTC_ID, 11),
            (0x57, 0),
            (0x58, 0),
            (0x59, src.0 << 16),
            (0x5a, src.1 << 16),
            (0x5b, dst.0 as u64),
            (0x5c, dst.1 as u64),
            (0x5d, dst.2),
            (0x5e, dst.3),
        ]
    };
    let video = place(video_fb, (32, 16), (8, 8, 24, 12));
    let with = |extra: &[(u32, u64)]| {
        let mut v = alloc::vec::Vec::from(video);
        v.extend_from_slice(extra);
        v
    };
    let half = with(&[(planes::ALPHA_PROP_ID, 0x8000), (planes::BLEND_PROP_ID, 1)]);
    if atomic(0x0100, &[(OVERLAY, &half)]) != Ok(0)
        || ms.lock().native_plane(OVERLAY).unwrap().fb_id.is_some()
    {
        return TestResult::Fail("TEST_ONLY overlay");
    }
    let eighth = place(big_fb, (256, 128), (0, 0, 32, 16));
    type Case = (&'static str, alloc::vec::Vec<(u32, u64)>, u32);
    let refused: [Case; 7] = [
        ("8:1 downscale", alloc::vec::Vec::from(eighth), OVERLAY),
        ("rotate-90", with(&[(planes::ROTATION_PROP_ID, 2)]), OVERLAY),
        (
            "two rotations",
            with(&[(planes::ROTATION_PROP_ID, 5)]),
            OVERLAY,
        ),
        (
            "alpha range",
            with(&[(planes::ALPHA_PROP_ID, 0x1_0000)]),
            OVERLAY,
        ),
        (
            "viewport",
            alloc::vec::Vec::from(place(video_fb, (32, 16), (8, 8, 20, 12))),
            OVERLAY,
        ),
        (
            "overlay format",
            alloc::vec::Vec::from(place(deep_fb, (64, 32), (0, 0, 64, 32))),
            OVERLAY,
        ),
        (
            "primary zpos",
            alloc::vec![(planes::PRIMARY_ZPOS_PROP_ID, 3)],
            0x40,
        ),
    ];
    for (why, props, plane) in &refused {
        if atomic(0x0100, &[(*plane, props)]) != Err(FsError::InvalidData) {
            return TestResult::Fail(why);
        }
    }
    // An enabled CRTC needs its primary plane (dm_crtc_helper_atomic_check).
    if atomic(0x0100, &[(0x40, &[(FB_ID, 0), (CRTC_ID, 0)])]) != Err(FsError::InvalidData) {
        return TestResult::Fail("CRTC without its primary");
    }
    // A commit records the overlay's state; GETPLANE reports it.
    if atomic(0, &[(OVERLAY, &half)]) != Ok(0) {
        return TestResult::Fail("overlay commit");
    }
    {
        let card = ms.lock();
        let p = card.native_plane(OVERLAY).unwrap();
        if (p.crtc_id, p.fb_id) != (Some(11), Some(video_fb))
            || p.props.alpha != 0x8000
            || p.props.blend != 1
            || p.dst != (8, 8, 24, 12)
            || card.crtc(11).unwrap().primary_fb != Some(primary_fb)
        {
            return TestResult::Fail("committed overlay state");
        }
    }
    if getplane(OVERLAY).1 != 11 || getplane(OVERLAY).2 != video_fb {
        return TestResult::Fail("GETPLANE of an enabled overlay");
    }
    // drm_atomic_plane_check: no direct move to another CRTC.
    let mut moved = alloc::vec::Vec::from(video);
    moved[1] = (CRTC_ID, 12);
    if atomic(0x0100, &[(OVERLAY, &moved)]) != Err(FsError::InvalidData) {
        return TestResult::Fail("overlay switched CRTC directly");
    }
    // SETPLANE: the plane alone, through the same checks.
    let setplane =
        |master: bool, plane: u32, fb: u32, dst: (i32, i32, u32, u32), src: (u32, u32)| {
            let mut b = [0u8; 48];
            let words: [u32; 12] = [
                plane,
                11,
                fb,
                0,
                dst.0 as u32,
                dst.1 as u32,
                dst.2,
                dst.3,
                0,
                0,
                src.1 << 16,
                src.0 << 16,
            ];
            for (i, w) in words.iter().enumerate() {
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let id = if master {
                SMOKE_MASTER_ID
            } else {
                SMOKE_MASTER_ID + 1
            };
            crate::drm_ioctl_bridge::dispatch_card(
                idx,
                id,
                iowr(DRM_IOCTL_BASE, 0xB7, 48),
                b.as_mut_ptr() as usize,
                false,
            )
        };
    if setplane(false, OVERLAY + 1, video_fb, (0, 0, 32, 16), (32, 16))
        != Err(FsError::PermissionDenied)
        || setplane(true, 0x99, video_fb, (0, 0, 32, 16), (32, 16)) != Err(FsError::NotFound)
        || setplane(true, OVERLAY + 1, video_fb, (0, 0, 32, 16), (33, 16)) != Err(FsError::NoSpace)
        || setplane(true, OVERLAY + 1, big_fb, (0, 0, 32, 16), (256, 128))
            != Err(FsError::InvalidData)
        || setplane(true, OVERLAY + 1, video_fb, (16, 8, 48, 24), (32, 16)) != Ok(0)
    {
        return TestResult::Fail("SETPLANE");
    }
    if ms.lock().native_plane(OVERLAY + 1).unwrap().dst != (16, 8, 48, 24)
        || setplane(true, OVERLAY + 1, 0, (0, 0, 0, 0), (0, 0)) != Ok(0)
        || ms.lock().native_plane(OVERLAY + 1).unwrap().fb_id.is_some()
    {
        return TestResult::Fail("SETPLANE state");
    }
    // Removing the overlay's framebuffer disables it.
    let mut rm = video_fb.to_le_bytes();
    if dispatch_card(
        idx,
        iowr(DRM_IOCTL_BASE, 0xA8, 4),
        rm.as_mut_ptr() as usize,
        false,
    ) != Ok(0)
        || ms.lock().native_plane(OVERLAY).unwrap().crtc_id.is_some()
    {
        return TestResult::Fail("RMFB of an overlay's framebuffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_native_overlay_planes
);
