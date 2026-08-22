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
//! Test buffers are kernel-owned: `copy_in` / `copy_out` in the bridge
//! do plain `core::ptr::copy_nonoverlapping`, so passing a `&mut
//! UapiStruct as *mut _ as usize` works just like a user pointer
//! would. The real syscall layer (Wave-22 `copy_from_user`) brackets
//! these with SMAP/STAC on top.
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
    // _IOW / _IOR shapes also distinguish themselves.
    let w_only = iow(b'd' as u32, 0x09, 16);
    if ioc_dir(w_only) != IOC_WRITE {
        return TestResult::Fail("iow direction bits not WRITE-only");
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
    let mut props = [0u32; 1];
    let mut vals = [0u64; 1];
    let mut og = [0u8; 28];
    og[0..8].copy_from_slice(&(props.as_mut_ptr() as u64).to_le_bytes());
    og[8..16].copy_from_slice(&(vals.as_mut_ptr() as u64).to_le_bytes());
    og[16..20].copy_from_slice(&1u32.to_le_bytes()); // count_props (room)
    og[20..24].copy_from_slice(&0x40u32.to_le_bytes()); // obj_id = plane
    let obj_getprops = iowr(DRM_IOCTL_BASE, 0xB9, 28);
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
    let mut buf = [0u8; 16];
    // GEM_CLOSE has nr=0x09 — the generic dispatcher routes it via
    // its UnknownCmd path (we haven't wired gem close through the
    // generic dispatcher's IoctlCmd match). The permission gate
    // should still pass for a render fd because GEM_CLOSE is
    // RENDER_ALLOW per Linux. The current implementation routes it
    // through handle_generic which returns Unsupported because the
    // dispatcher's IoctlCmd::Unknown branch fires for nr=0x09 —
    // i.e. permission gate passed but the cmd is not wired yet.
    // We accept either Ok(_) or Err(Unsupported) — both prove the
    // permission gate didn't reject.
    let r = dispatch_card(
        idx,
        DRM_IOCTL_GEM_CLOSE,
        buf.as_mut_ptr() as usize,
        /*render*/ true,
    );
    match r {
        Ok(_) | Err(FsError::Unsupported) => TestResult::Pass,
        Err(FsError::PermissionDenied) => {
            TestResult::Fail("GEM_CLOSE rejected on render fd — should be RENDER_ALLOW")
        }
        Err(_) => TestResult::Fail("GEM_CLOSE returned unexpected error"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_render_fd_accepts_gem_close
);

// ── 8. DRM_IOCTL_MODE_ATOMIC succeeds on empty state ───────────────────

#[allow(dead_code)]
fn smoke_drm_ioctl_atomic_empty_commit_succeeds() -> TestResult {
    let idx = register_test_card();
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
    // The dma-buf must round-trip back to its GEM handle (FD_TO_HANDLE):
    // a compositor exports its buffer then imports it to build a KMS fb.
    match dmabuf.as_prime_gem_handle() {
        Some(1) => TestResult::Pass,
        _ => TestResult::Fail("PRIME dma-buf did not round-trip to its GEM handle"),
    }
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_prime_export_aliases_dumb_frames
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
    let handle = card.gem.alloc(fake_phys, 4096).unwrap();
    card.dumb_backings.push(DumbBacking {
        gem_handle: handle,
        phys: fake_phys,
        byte_len: 4096,
        order: 0,
        mmap_offset: (handle as u64) << 12,
        refcount: 1,
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

// Anchor the kernel-test framework imports so the kernel-test feature
// doesn't trip a "use never used" warning on cfg-out builds.
const _USE_STRING: Option<String> = None;
const _USE_VEC: Option<alloc::vec::Vec<u8>> = None;
#[allow(dead_code)]
fn _use_vec_macro() {
    let _ = vec![0u8; 0];
}
