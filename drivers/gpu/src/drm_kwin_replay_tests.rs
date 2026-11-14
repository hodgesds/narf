//! KWin's buffer traffic on a Navi22-shaped card, replayed through the
//! device files a compositor and its clients hold, to prove that nothing
//! it does keeps a buffer, a pin or a framebuffer behind.
//!
//! The sequence is the one KWin 6.8 issues on the DRM backend, taken from a
//! hardware boot's request trace: a three-buffer swapchain allocated on a
//! second open of the card (KWin's GBM device) and brought to the master
//! open with FD_TO_HANDLE, ADDFB2, GEM_CLOSE; per frame, a client buffer
//! imported the same way, tried on an overlay plane and for direct scanout
//! with TEST_ONLY commits, then CLOSEFB; one real commit per frame with a
//! flip event; a client that dies with its buffer still imported; and the
//! greeter-to-session hand-over, where the old master closes a framebuffer
//! that is still on screen.
#![cfg(target_arch = "x86_64")]

use crate::amdgpu_gem::{self as gem, GemObject, VramHeap};
use crate::drm::card::{Card, Crtc};
use crate::drm_devfs_bridge::DriCardFile;
use crate::drm_uapi::{self, DrmModeAtomicUapi};
use alloc::sync::{Arc, Weak};
use alloc::{format, vec, vec::Vec};
use narf_filesystem::{FileOps, FsError, IoctlContext};
use narf_kernel_test::{kernel_test_in, TestResult};

const CRTC: u32 = 0x4170;
const PRIMARY: u32 = crate::drm_native_planes::PRIMARY_PLANE_ID_BASE;
const PAGE: u64 = 4096;
const XR24: u32 = 0x3432_5258;
/// 64x12 at a 256-byte pitch: one page.
const WIDTH: u32 = 64;
const HEIGHT: u32 = 12;
const PITCH: u32 = 256;

const FB_ID: u32 = 0x55;
const CRTC_ID: u32 = 0x56;
const SRC_X: u32 = 0x57;
const SRC_Y: u32 = 0x58;
const SRC_W: u32 = 0x59;
const SRC_H: u32 = 0x5a;
const CRTC_X: u32 = 0x5b;
const CRTC_Y: u32 = 0x5c;
const CRTC_W: u32 = 0x5d;
const CRTC_H: u32 = 0x5e;
const IN_FENCE_FD: u32 = 0x5f;

const TEST_ONLY: u32 = 0x100;
const NONBLOCK: u32 = 0x200;
const PAGE_FLIP_EVENT: u32 = 0x1;

/// Kernel-test ioctl arguments are kernel memory.
struct Kernel;
impl IoctlContext for Kernel {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        // SAFETY: every address the replay passes names a live local buffer
        // of at least this length.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        // SAFETY: as `read`.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), address as *mut u8, source.len());
        }
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        true
    }
}

struct Fixture {
    index: u32,
    mode: Arc<narf_lib::sync::IrqSafeSpinLock<Card>>,
    _bar: Vec<u8>,
}

impl Fixture {
    /// Navi22 as it publishes itself: a native linear 8888 primary per
    /// CRTC under two overlays, a cursor plane, and a client VRAM heap.
    fn new(pages: usize) -> Option<Self> {
        let mut card = Card::new("amdgpu", "KWin replay fixture", (3, 60, 0));
        card.native_atomic = true;
        card.plane_formats = Some(&[XR24, 0x3432_5241]);
        card.overlay_formats = Some(&crate::amdgpu_navi48_kms::PLANE_FORMATS);
        card.crtcs.push(Crtc {
            id: CRTC,
            mode: Some(crate::Mode {
                width: WIDTH,
                height: HEIGHT,
                refresh_hz: 60,
                bpp: 32,
            }),
            enabled: true,
            primary_fb: None,
            x: 0,
            y: 0,
        });
        card.native_planes = crate::drm_native_planes::dcn30_planes_for(&[], &[CRTC]);
        let iface = Arc::new(crate::drm_devfs_bridge::AmdgpuCard::new(
            format!("card{}", crate::drm_registry::count()),
            0x1002,
            0x73df,
            0,
            0,
            None,
        ));
        let index = crate::drm_registry::register_drm_card_with_state(iface, card);
        let mode = crate::drm_registry::mode_state(index)?;
        let mut bar = vec![0u8; pages * PAGE as usize];
        let map = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xbe00_0000),
            virt: bar.as_mut_ptr() as u64,
            len: bar.len() as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: fixture-owned bytes outlive the heap and every device file.
        let pool =
            unsafe { crate::amdgpu_vram::Pool::from_owned_range(map, 0x8_0000_0000) }.ok()?;
        gem::register_vram_heap(
            index,
            VramHeap {
                pool,
                fb_base: 0x8_0000_0000,
                fb_offset: 0x8_0000_0000,
                unmapped: None,
            },
        );
        Some(Self {
            index,
            mode,
            _bar: bar,
        })
    }
    fn vram_used(&self) -> u64 {
        gem::vram_heap_usage(self.index).map_or(u64::MAX, |u| u.visible.1)
    }
    fn fbs(&self) -> usize {
        self.mode.lock().framebuffers.len()
    }
    /// The buffer framebuffer `fb` holds.
    fn object(&self, fb: u32) -> Option<Arc<GemObject>> {
        let card = self.mode.lock();
        card.framebuffer(fb)
            .ok()?
            .bo
            .as_ref()
            .map(|bo| bo.object.clone())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.mode.lock().framebuffers.clear();
        gem::unregister_vram_heap(self.index);
    }
}

fn ioctl(file: &dyn FileOps, cmd: u32, arg: usize) -> Result<u64, FsError> {
    narf_scheduler::block_on_spin(file.ioctl_user(cmd, arg as u64, &Kernel))
}

/// GEM_CREATE of one page in `domains`; the new handle.
fn create(file: &dyn FileOps, domains: u32) -> Result<u32, FsError> {
    let mut req = [0u8; 32];
    req[..8].copy_from_slice(&PAGE.to_le_bytes());
    req[8..16].copy_from_slice(&PAGE.to_le_bytes());
    req[16..24].copy_from_slice(&u64::from(domains).to_le_bytes());
    ioctl(file, 0xc020_6440, req.as_mut_ptr() as usize)?;
    Ok(u32::from_le_bytes(req[..4].try_into().unwrap()))
}

fn gem_close(file: &dyn FileOps, handle: u32) -> Result<u64, FsError> {
    let mut req = [0u8; 8];
    req[..4].copy_from_slice(&handle.to_le_bytes());
    ioctl(
        file,
        drm_uapi::DRM_IOCTL_GEM_CLOSE,
        req.as_mut_ptr() as usize,
    )
}

/// ADDFB2 (with modifiers, LINEAR) of `handle`; the framebuffer id.
fn addfb2(file: &dyn FileOps, handle: u32) -> Result<u32, FsError> {
    let mut arg = [0u8; 104];
    for (offset, value) in [
        (4, WIDTH),
        (8, HEIGHT),
        (12, XR24),
        (16, 2u32),
        (20, handle),
        (36, PITCH),
    ] {
        arg[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    ioctl(
        file,
        drm_uapi::DRM_IOCTL_MODE_ADDFB2,
        arg.as_mut_ptr() as usize,
    )?;
    Ok(u32::from_le_bytes(arg[..4].try_into().unwrap()))
}

fn closefb(file: &dyn FileOps, fb: u32) -> Result<u64, FsError> {
    let mut req = [0u8; 8];
    req[..4].copy_from_slice(&fb.to_le_bytes());
    ioctl(
        file,
        drm_uapi::iowr(drm_uapi::DRM_IOCTL_BASE, 0xD0, 8),
        req.as_mut_ptr() as usize,
    )
}

/// KWin's import of a buffer another open allocated: PRIME export there,
/// FD_TO_HANDLE and ADDFB2 here, then GEM_CLOSE of the imported handle
/// (DrmGpu::importBuffer). The framebuffer id and the dma-buf "fd", which
/// the wl_buffer keeps for as long as the client buffer lives.
fn import_fb(
    kms: &DriCardFile,
    owner: &dyn FileOps,
    handle: u32,
) -> Result<(u32, Arc<dyn FileOps>), FsError> {
    let dmabuf = owner.drm_prime_export_file(handle)?;
    let imported = kms.drm_prime_import_file(&dmabuf)?;
    let fb = addfb2(kms, imported);
    gem_close(kms, imported)?;
    Ok((fb?, dmabuf))
}

/// One plane's part of an atomic request, as KWin orders it.
struct Request {
    objects: Vec<u32>,
    counts: Vec<u32>,
    props: Vec<u32>,
    values: Vec<u64>,
}
impl Request {
    fn new() -> Self {
        Self {
            objects: Vec::new(),
            counts: Vec::new(),
            props: Vec::new(),
            values: Vec::new(),
        }
    }
    fn off(mut self, plane: u32) -> Self {
        self.objects.push(plane);
        self.counts.push(3);
        self.props.extend_from_slice(&[IN_FENCE_FD, FB_ID, CRTC_ID]);
        self.values.extend_from_slice(&[u64::MAX, 0, 0]);
        self
    }
    fn show(mut self, plane: u32, fb: u32, width: u32) -> Self {
        self.objects.push(plane);
        self.counts.push(11);
        self.props.extend_from_slice(&[
            CRTC_H,
            CRTC_W,
            CRTC_Y,
            CRTC_X,
            SRC_H,
            SRC_W,
            SRC_Y,
            SRC_X,
            IN_FENCE_FD,
            FB_ID,
            CRTC_ID,
        ]);
        self.values.extend_from_slice(&[
            u64::from(HEIGHT),
            u64::from(width),
            0,
            0,
            u64::from(HEIGHT) << 16,
            u64::from(width) << 16,
            0,
            0,
            u64::MAX,
            u64::from(fb),
            u64::from(CRTC),
        ]);
        self
    }
    fn send(mut self, kms: &DriCardFile, flags: u32) -> Result<u64, FsError> {
        let mut header = DrmModeAtomicUapi {
            flags,
            count_objs: self.objects.len() as u32,
            objs_ptr: self.objects.as_mut_ptr() as u64,
            count_props_ptr: self.counts.as_mut_ptr() as u64,
            props_ptr: self.props.as_mut_ptr() as u64,
            prop_values_ptr: self.values.as_mut_ptr() as u64,
            user_data: 0x6b77_696e,
            ..Default::default()
        };
        ioctl(
            kms,
            drm_uapi::DRM_IOCTL_MODE_ATOMIC,
            (&mut header as *mut DrmModeAtomicUapi) as usize,
        )
    }
}

/// Read the flip event of the commit just made (its simulated vblank is at
/// most a frame away).
fn flip_event(kms: &DriCardFile) -> bool {
    let deadline = narf_time::wall::monotonic_ns().saturating_add(500_000_000);
    let mut event = [0u8; 32];
    loop {
        match narf_scheduler::block_on_spin(kms.read(0, &mut event)) {
            Ok(32) => {
                return u64::from_le_bytes(event[8..16].try_into().unwrap()) == 0x6b77_696e;
            }
            Err(FsError::WouldBlock) if narf_time::wall::monotonic_ns() < deadline => {
                core::hint::spin_loop();
            }
            _ => return false,
        }
    }
}

struct Planes {
    overlays: Vec<u32>,
    cursor: u32,
}

/// A full-screen primary frame, overlays and cursor plane off.
fn frame(planes: &Planes, fb: u32) -> Request {
    let mut request = Request::new();
    for &overlay in &planes.overlays {
        request = request.off(overlay);
    }
    request.off(planes.cursor).show(PRIMARY, fb, WIDTH)
}

fn kwin_frames_and_probes_return_every_buffer_pin_and_framebuffer() -> TestResult {
    let Some(f) = Fixture::new(32) else {
        return TestResult::Fail("fixture");
    };
    let planes = {
        let card = f.mode.lock();
        Planes {
            overlays: crate::drm_native_planes::overlay_ids(&card),
            cursor: crate::drm_native_planes::cursor_ids(&card)[0],
        }
    };
    let vram = crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM;
    let gtt = crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_GTT;
    let (base_vram, base_gtt) = (f.vram_used(), gem::gtt_used());

    // The master open, then KWin's second open of the card (its GBM
    // device) and a client's open (GEM buffers live per open on either
    // node; a later open of the card node is no master).
    let (Some(kms), Some(gbm), Some(client)) = (
        DriCardFile::new(f.index),
        DriCardFile::new(f.index),
        DriCardFile::new(f.index),
    ) else {
        return TestResult::Fail("opens");
    };

    // The swapchain: three buffers of the GBM open, a framebuffer each.
    let mut swapchain = Vec::new();
    for _ in 0..3 {
        let Ok(handle) = create(&gbm, vram) else {
            return TestResult::Fail("swapchain GEM_CREATE");
        };
        let Ok((fb, dmabuf)) = import_fb(&kms, &gbm, handle) else {
            return TestResult::Fail("swapchain import or ADDFB2");
        };
        swapchain.push((fb, handle, dmabuf));
    }
    let chain: Vec<Arc<GemObject>> = swapchain
        .iter()
        .filter_map(|&(fb, _, _)| f.object(fb))
        .collect();
    if chain.len() != 3 || f.vram_used() != base_vram + 3 * PAGE || f.fbs() != 3 {
        return TestResult::Fail("swapchain is not three VRAM buffers and framebuffers");
    }

    for i in 0..48usize {
        let (shown, _, _) = swapchain[i % 3];
        // The client's buffer for this frame: VRAM mostly, system memory
        // (a GTT buffer) every fourth frame.
        let system = i % 4 == 3;
        let Ok(handle) = create(&client, if system { gtt } else { vram }) else {
            return TestResult::Fail("client GEM_CREATE");
        };
        let Ok((client_fb, dmabuf)) = import_fb(&kms, &client, handle) else {
            return TestResult::Fail("client import or ADDFB2");
        };
        let Some(buffer) = f.object(client_fb) else {
            return TestResult::Fail("client framebuffer holds no buffer");
        };
        if buffer.system() != system {
            return TestResult::Fail("client buffer placement");
        }
        // The probes: the client buffer on an overlay over the frame, then
        // alone for direct scanout. Whatever the display answers, a probe
        // changes nothing: no pin, no migration, no plane state.
        let before = f.mode.lock().crtcs[0].primary_fb;
        let mut overlay = Request::new();
        for &id in &planes.overlays[1..] {
            overlay = overlay.off(id);
        }
        let _ = overlay
            .off(planes.cursor)
            .show(planes.overlays[0], client_fb, WIDTH / 2)
            .show(PRIMARY, shown, WIDTH)
            .send(&kms, TEST_ONLY | NONBLOCK);
        let _ = frame(&planes, client_fb).send(&kms, TEST_ONLY | NONBLOCK);
        if buffer.pinned()
            || buffer.system() != system
            || chain.iter().any(|o| o.pinned())
            || f.mode.lock().crtcs[0].primary_fb != before
            || f.mode
                .lock()
                .native_planes
                .iter()
                .any(|p| p.fb_id == Some(client_fb))
        {
            return TestResult::Fail("a TEST_ONLY probe pinned, moved or showed a buffer");
        }
        // The frame itself.
        if frame(&planes, shown).send(&kms, PAGE_FLIP_EVENT | NONBLOCK) != Ok(0) {
            return TestResult::Fail("real commit refused");
        }
        if f.mode.lock().crtcs[0].primary_fb != Some(shown) || !flip_event(&kms) {
            return TestResult::Fail("commit did not show the frame or lost its flip event");
        }
        // Every eighth frame the client's buffer is scanned out directly,
        // which moves a system buffer to VRAM (prepare_fb) and pins it for
        // as long as it is shown.
        if i % 8 == 7 {
            if frame(&planes, client_fb).send(&kms, PAGE_FLIP_EVENT | NONBLOCK) != Ok(0)
                || !flip_event(&kms)
                || buffer.system()
            {
                return TestResult::Fail("direct scanout of a client buffer");
            }
            if frame(&planes, shown).send(&kms, PAGE_FLIP_EVENT | NONBLOCK) != Ok(0)
                || !flip_event(&kms)
            {
                return TestResult::Fail("commit back to the swapchain");
            }
        }
        // KWin drops the client framebuffer; the client frees the buffer.
        // Every sixth frame the client dies first, with its buffer still
        // imported: the framebuffer and the dma-buf keep it until KWin
        // lets go.
        let weak: Weak<GemObject> = Arc::downgrade(&buffer);
        drop(buffer);
        if i % 6 == 5 {
            let Some(crashed) = DriCardFile::new(f.index) else {
                return TestResult::Fail("second client open");
            };
            let Ok(h) = create(&crashed, vram) else {
                return TestResult::Fail("second client GEM_CREATE");
            };
            let Ok((fb, held)) = import_fb(&kms, &crashed, h) else {
                return TestResult::Fail("second client import");
            };
            let Some(orphan) = f.object(fb).map(|o| Arc::downgrade(&o)) else {
                return TestResult::Fail("second client framebuffer");
            };
            drop(crashed);
            if orphan.upgrade().is_none() {
                return TestResult::Fail("a framebuffer did not keep its dead client's buffer");
            }
            if closefb(&kms, fb) != Ok(0) {
                return TestResult::Fail("CLOSEFB of a dead client's framebuffer");
            }
            drop(held);
            if orphan.upgrade().is_some() {
                return TestResult::Fail("a dead client's buffer outlived its last holder");
            }
        }
        if closefb(&kms, client_fb) != Ok(0) || gem_close(&client, handle) != Ok(0) {
            return TestResult::Fail("CLOSEFB or the client's GEM_CLOSE");
        }
        drop(dmabuf);
        if weak.upgrade().is_some() {
            return TestResult::Fail("client buffer leaked");
        }
        if f.fbs() != 3
            || f.vram_used() != base_vram + 3 * PAGE
            || gem::gtt_used() != base_gtt
            || chain.iter().any(|o| o.pinned())
        {
            return TestResult::Fail("a frame left a framebuffer, VRAM, system pages or a pin");
        }
    }

    // KWin exits: CLOSEFB of every framebuffer (the last frame's is still
    // on screen and stays, owned by no file), then both opens close.
    let (shown, _, _) = swapchain[47 % 3];
    let weak: Vec<Weak<GemObject>> = chain.iter().map(Arc::downgrade).collect();
    drop(chain);
    for (fb, handle, dmabuf) in swapchain {
        if closefb(&kms, fb) != Ok(0) || gem_close(&gbm, handle) != Ok(0) {
            return TestResult::Fail("swapchain CLOSEFB or GEM_CLOSE");
        }
        drop(dmabuf);
    }
    drop(kms);
    drop(gbm);
    drop(client);
    if f.fbs() != 1
        || f.mode.lock().crtcs[0].primary_fb != Some(shown)
        || weak.iter().filter(|w| w.upgrade().is_some()).count() != 1
        || f.vram_used() != base_vram + PAGE
    {
        return TestResult::Fail("the old master left more than its on-screen framebuffer");
    }

    // The session compositor takes over and shows its own frame: the old
    // master's framebuffer and buffer go with that commit.
    let Some(session) = DriCardFile::new(f.index) else {
        return TestResult::Fail("session open");
    };
    let Ok(handle) = create(&session, vram) else {
        return TestResult::Fail("session GEM_CREATE");
    };
    let Ok(fb) = addfb2(&session, handle) else {
        return TestResult::Fail("session ADDFB2");
    };
    if frame(&planes, fb).send(&session, PAGE_FLIP_EVENT | NONBLOCK) != Ok(0)
        || !flip_event(&session)
    {
        return TestResult::Fail("session commit");
    }
    if f.fbs() != 1
        || weak.iter().any(|w| w.upgrade().is_some())
        || f.vram_used() != base_vram + PAGE
    {
        return TestResult::Fail("the old master's closed framebuffer outlived its last frame");
    }
    drop(session);
    if f.fbs() != 0 || f.vram_used() != base_vram || gem::gtt_used() != base_gtt {
        return TestResult::Fail("closing the last open left a framebuffer or memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/kwin_replay",
    kwin_frames_and_probes_return_every_buffer_pin_and_framebuffer
);

/// drm_show_fdinfo on the device files themselves: each open reports its
/// own client id and the memory its handles hold, a buffer shared between
/// two opens in both, and system pages apart from VRAM.
fn device_files_report_their_memory_in_fdinfo() -> TestResult {
    let Some(f) = Fixture::new(8) else {
        return TestResult::Fail("fixture");
    };
    let (Some(kms), Some(client)) = (DriCardFile::new(f.index), DriCardFile::new(f.index)) else {
        return TestResult::Fail("opens");
    };
    let vram = crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM;
    let gtt = crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_GTT;
    let (Ok(shared), Ok(_private), Ok(_system)) = (
        create(&client, vram),
        create(&client, vram),
        create(&client, gtt),
    ) else {
        return TestResult::Fail("client buffers");
    };
    let Ok(dmabuf) = client.drm_prime_export_file(shared) else {
        return TestResult::Fail("export");
    };
    if kms.drm_prime_import_file(&dmabuf).is_err() {
        return TestResult::Fail("import");
    }
    let text = |file: &DriCardFile| {
        let mut out = alloc::string::String::new();
        file.show_fdinfo(&mut out);
        out
    };
    let (of_client, of_kms) = (text(&client), text(&kms));
    let id = |text: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix("drm-client-id:\t"))
            .and_then(|v| v.parse::<u64>().ok())
    };
    if !of_client.starts_with("drm-driver:\tamdgpu\ndrm-client-id:\t")
        || !of_client.contains("drm-memory-vram:\t8 KiB\n")
        || !of_client.contains("drm-memory-gtt: \t4 KiB\n")
        || !of_client.contains("amd-requested-vram:\t8 KiB\n")
        || !of_client.contains("amd-requested-gtt:\t4 KiB\n")
    {
        return TestResult::Fail("the client's fdinfo");
    }
    if !of_kms.contains("drm-memory-vram:\t4 KiB\n")
        || !of_kms.contains("drm-memory-gtt: \t0 KiB\n")
        || id(&of_kms).is_none()
        || id(&of_kms) == id(&of_client)
    {
        return TestResult::Fail("the importer's fdinfo");
    }
    // The same figures as the card's mem_info_* attributes read them.
    use crate::amdgpu_gem::accounting::{mem_info, MemInfo};
    if mem_info(f.index, MemInfo::VramTotal) != 8 * PAGE
        || mem_info(f.index, MemInfo::VisVramUsed) != 2 * PAGE
        || mem_info(f.index, MemInfo::GttUsed) < PAGE
    {
        return TestResult::Fail("mem_info");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/kwin_replay",
    device_files_report_their_memory_in_fdinfo
);

/// An allocation the heap cannot hold, through the device file: the
/// client gets its errno, the card counts the failure (and reports the
/// heap), and the ioctl is named in the log as one that failed for lack
/// of memory. None of it is silent.
fn a_refused_allocation_is_counted_and_named() -> TestResult {
    let Some(f) = Fixture::new(1) else {
        return TestResult::Fail("fixture");
    };
    let Some(client) = DriCardFile::new(f.index) else {
        return TestResult::Fail("open");
    };
    // Two pages of VRAM-only DISCARDABLE memory on a one-page heap: no
    // GTT fallback (amdgpu_bo_create), nothing to evict.
    let mut req = [0u8; 32];
    req[..8].copy_from_slice(&(2 * PAGE).to_le_bytes());
    req[16..24]
        .copy_from_slice(&u64::from(crate::amdgpu_uapi::AMDGPU_GEM_DOMAIN_VRAM).to_le_bytes());
    req[24..32].copy_from_slice(
        &u64::from(crate::amdgpu_uapi::AMDGPU_GEM_CREATE_DISCARDABLE).to_le_bytes(),
    );
    let before = req;
    let failures = crate::amdgpu_gem::accounting::failures(f.index);
    if ioctl(&client, 0xc020_6440, req.as_mut_ptr() as usize) != Err(FsError::NoSpace)
        || req != before
    {
        return TestResult::Fail("the allocation was not refused cleanly");
    }
    if crate::amdgpu_gem::accounting::failures(f.index) != failures + 1 {
        return TestResult::Fail("the refused allocation was not counted");
    }
    if !crate::drm_ioctl_bridge::drm_fd_failure_noted(0x40) {
        return TestResult::Fail("the failing ioctl was not named");
    }
    if f.vram_used() != 0 || f.fbs() != 0 {
        return TestResult::Fail("the refused allocation left something behind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/kwin_replay",
    a_refused_allocation_is_counted_and_named
);
