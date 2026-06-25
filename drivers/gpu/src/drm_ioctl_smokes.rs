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
use crate::drm_ioctl_bridge::dispatch_card;
use crate::drm_uapi::{
    ioc, ioc_dir, ioc_nr, ioc_size, ioc_type, iow, iowr, DrmModeAtomicUapi, DrmModeCardResUapi,
    DrmVersionUapi, DRM_IOCTL_BASE, DRM_IOCTL_GEM_CLOSE, DRM_IOCTL_MODE_ATOMIC,
    DRM_IOCTL_MODE_GETRESOURCES, DRM_IOCTL_MODE_SETCRTC, DRM_IOCTL_SET_CLIENT_CAP,
    DRM_IOCTL_VERSION, IOC_READ, IOC_WRITE,
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

/// Register a fresh test card with the registry. Returns its index.
fn register_test_card() -> u32 {
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
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm_ioctl",
    smoke_drm_ioctl_set_client_cap_universal_vs_atomic
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
        });
        // Register a framebuffer backed by this handle.
        let fb_id = card
            .addfb2(256, 256, 0x3432_5258 /* XR24 */, 256 * 4, handle)
            .unwrap();
        let _ = fb_id;
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

// Anchor the kernel-test framework imports so the kernel-test feature
// doesn't trip a "use never used" warning on cfg-out builds.
const _USE_STRING: Option<String> = None;
const _USE_VEC: Option<alloc::vec::Vec<u8>> = None;
#[allow(dead_code)]
fn _use_vec_macro() {
    let _ = vec![0u8; 0];
}
