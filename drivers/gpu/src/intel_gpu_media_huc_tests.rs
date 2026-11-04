// MTL/Arrow media-GT HuC conversations through the production MediaGuc,
// GuCGt, GuCBoot and scheduler owners on the GuC model. Literal identities
// follow MIT Linux b90c984d: xe_uc.c::xe_uc_load_hw, xe_huc.c::{xe_huc_init,
// xe_huc_upload,xe_huc_auth,huc_auth_modes}, xe_uc_fw.c::{parse_headers,
// uc_fw_copy,uc_fw_xfer}, xe_wopcm.c::xe_wopcm_init, xe_guc.c::
// xe_guc_auth_huc, xe_query.c::query_uc_fw_version and regs/xe_guc_regs.h,
// with every GuC register at the media GSI offset.
use super::media_gt_sched::{media_tick, Hw};
use super::*;
use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_exec::PpgttProbeResult;
use crate::intel_gpu_gt::media::{query_huc, MediaGt, MediaGuc, MediaGucError, MediaGucState};
use crate::intel_gpu_huc as huc;
use crate::intel_gpu_render::{tests::User, DeviceInfo, RenderFile};
use crate::intel_gpu_uapi::{put32, put64, u32_at};
use crate::intel_gpu_user::{UserBackend, UserBatch, UserContext, UserStatus};
use alloc::{boxed::Box, sync::Arc};
use core::future::Future;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Waker};
use narf_filesystem::{FsError, FsFuture};

/// VCS0, VCS2 and VECS0 present (positive-polarity media fuse).
const FUSE: u32 = 0x0001_0005;
/// RPM_CONFIG0: 19.2 MHz crystal, CTC shift 3.
const RPM_CONFIG0: u32 = (1 << 3) | (3 << 1);
/// gsc_cpd_header_v2 marker "$CPD".
const CPD_MARKER: u32 = 0x4450_4324;
/// The huc_fw entry: the CSS inside the GSC-headered image.
const CSS_AT: u32 = 0x100;
/// DMA_COPY_SIZE: the CSS header plus 16 bytes of uCode.
const UPLOAD: u32 = 128 + 16;
/// xe_uc_fw_rsa_offset: css_offset + CSS header + uCode.
const RSA: u32 = CSS_AT + UPLOAD;
/// CSS, uCode, the 256-byte RSA and a two-byte tail past the last dword.
const FILE: usize = CSS_AT as usize + 128 + 16 + 256 + 2;
/// HUC_KERNEL_LOAD_INFO through GT1's view (MEDIA_GT_GSI_OFFSET).
const MEDIA_HUC_STATUS: u64 = 0x38c1dc;

/// Media GuC answer to AUTHENTICATE_HUC: 0 ACK and status bit, 1 ACK only,
/// 2 RESPONSE_FAILURE. Kernel smokes run sequentially.
static MODE: AtomicU32 = AtomicU32::new(0);
static AUTHS: AtomicU32 = AtomicU32::new(0);

fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// An `i915/mtl_huc_gsc.bin`-shaped image: a CPD with HUCP.man (release
/// 9.9.9.9, never reported) and huc_fw (CSS sw_version 8.5.4, reported).
pub(super) fn huc_gsc() -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; FILE];
    put(&mut bytes, 0, CPD_MARKER);
    put(&mut bytes, 4, 2);
    bytes[8] = 2;
    bytes[9] = 1;
    bytes[10] = 20;
    for (index, (name, offset)) in [("HUCP.man", 0x80), ("huc_fw", CSS_AT)]
        .into_iter()
        .enumerate()
    {
        let at = 20 + index * 24;
        bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
        put(&mut bytes, at + 12, offset);
    }
    for field in 0..4 {
        bytes[0x80 + 36 + field * 2..][..2].copy_from_slice(&9u16.to_le_bytes());
    }
    let css = CSS_AT as usize;
    for (at, value) in [
        (0, 6),
        (4, 161),
        (8, 0x10000),
        (16, 0x8086),
        (24, 165),
        (28, 64),
        (32, 64),
        (36, 1),
        (64, 0x0008_0504),
        (128, 0x1234_5678),
        (144, 0xabcd_ef01),
    ] {
        put(&mut bytes, css + at, value);
    }
    bytes[FILE - 2] = 0xab;
    bytes[FILE - 1] = 0xcd;
    bytes
}

/// The media GuC's side of xe_guc_auth_huc on the media CT.
pub(super) fn service_auth(w: &Window, memory: &Words, id: u16, request: &[u32]) {
    assert_eq!(request.len(), 2);
    assert_eq!(request[0], 0x4000, "AUTHENTICATE_HUC as a normal request");
    assert!((0x4000..=0x7eff).contains(&id));
    {
        let d = w.0.borrow();
        let (base, words) = d
            .memory
            .iter()
            .find(|(_, words)| words.borrow()[0] == CPD_MARKER)
            .expect("staged HuC object");
        // xe_huc_auth: the whole object's GGTT base + xe_uc_fw_rsa_offset.
        assert_eq!(request[1], base + RSA);
        assert_eq!(words.borrow()[RSA as usize / 4], 0xabcd_ef01);
    }
    AUTHS.fetch_add(1, Ordering::Relaxed);
    match MODE.load(Ordering::Relaxed) {
        0 => {
            super::huc_native::response(memory, id, 0xf000_0000);
            w.0.borrow_mut().regs.insert(MEDIA_HUC_STATUS, 1);
        }
        1 => super::huc_native::response(memory, id, 0xf000_0000),
        2 => super::huc_native::response(memory, id, 0xe000_0030),
        _ => panic!("invalid media HuC fixture mode"),
    }
}

fn guc_firmware() -> GuCFirmware {
    GuCFirmware::from_fixture(MTL, &image()).unwrap()
}

pub(super) fn start(
    w: &Window,
    arena: &Arena,
    huc: Option<(&huc::Firmware, bool)>,
) -> MediaGuc<Window, Arena> {
    start_at(w, arena, huc, 0)
}

/// `start` at `now` on the fixture clock (an incarnation after a stop).
pub(super) fn start_at(
    w: &Window,
    arena: &Arena,
    huc: Option<(&huc::Firmware, bool)>,
    now: u64,
) -> MediaGuc<Window, Arena> {
    let media = MediaGt::initialized_for_test(MTL, MEDIA_GMD, FUSE);
    w.0.borrow_mut().regs.insert(0x380d00, RPM_CONFIG0);
    MediaGuc::start(
        w.clone(),
        arena.clone(),
        &guc_firmware(),
        huc,
        media_config(),
        &media,
        now,
    )
    .unwrap()
}

/// GT1 registers, the media mailbox and the absolute media engine banks.
fn gt1_owned(offset: u64) -> bool {
    media_owned(offset) || (0x1c0000..0x200000).contains(&offset)
}

/// One tick per millisecond. A HuC DMA is recorded while in flight, before
/// the model retires it: source, its space, destination, its space, size
/// and the GuC status (MIA still in reset).
fn run(
    guc: &mut MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    from: u64,
    dma: &mut Vec<[u32; 6]>,
    done: impl Fn(&Poll<Result<MediaGucState, MediaGucError>>) -> bool,
) -> (u64, Poll<Result<MediaGucState, MediaGucError>>) {
    for tick in 0..2000 {
        let now = from + tick * 1_000_000;
        {
            let d = w.0.borrow();
            let r = |reg: u64| d.regs.get(&reg).copied().unwrap_or(0);
            if r(0x38c314) & 0x201 == 0x201 {
                dma.push([
                    r(0x38c300),
                    r(0x38c304),
                    r(0x38c308),
                    r(0x38c30c),
                    r(0x38c310),
                    r(0x38c000),
                ]);
            }
        }
        let polled = media_tick(guc, w, hw, now);
        if done(&polled) {
            return (now, polled);
        }
    }
    panic!("media GuC made no progress");
}

fn stop(guc: &mut MediaGuc<Window, Arena>, w: &Window, hw: &mut Hw, from: u64) {
    guc.begin_stop(from);
    assert_eq!(guc.huc_version(|| true), None);
    let mut dma = Vec::new();
    let (_, polled) = run(guc, w, hw, from + 1, &mut dma, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    assert!(dma.is_empty());
}

/// After a verified stop reclaimed every allocation: restart GGTT placement
/// so the next incarnation's ADS lands where the CT model expects it.
pub(super) fn reclaimed(w: &Window, arena: &Arena) {
    assert_eq!(arena.live_allocations(), 0);
    let mut d = w.0.borrow_mut();
    d.next = 0x2000_0000;
    d.synced.clear();
    d.cpu_synced.clear();
}

fn huc_base(w: &Window) -> u32 {
    *w.0.borrow()
        .memory
        .iter()
        .find(|(_, words)| words.borrow()[0] == CPD_MARKER)
        .expect("staged HuC object")
        .0
}

fn positions(w: &Window, from: usize, pair: (u64, u32)) -> Vec<usize> {
    w.0.borrow().writes[from..]
        .iter()
        .enumerate()
        .filter(|(_, write)| **write == pair)
        .map(|(at, _)| at)
        .collect()
}

#[derive(Debug)]
struct HucBackend(Option<(u8, u8, u8)>);
impl UserBackend for HucBackend {
    fn status(&self) -> Option<UserStatus> {
        Some(UserStatus {
            epoch: 7,
            platform: MTL,
            submission_version: (1, 0, 0),
            engines: Default::default(),
        })
    }
    fn native_xe(&self) -> bool {
        true
    }
    fn huc_version(&self) -> FsFuture<'_, (u8, u8, u8)> {
        let version = self.0;
        Box::pin(async move { version.ok_or(FsError::NoDevice) })
    }
    fn submit<'a>(
        &'a self,
        _: Arc<UserContext>,
        _: UserBatch,
    ) -> FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        Box::pin(async { Err(FsError::NoDevice) })
    }
}

/// DRM_XE_DEVICE_QUERY_UC_FW_VERSION for XE_QUERY_UC_TYPE_HUC on an MTL
/// card whose backend answers `version`: (branch, major, minor, patch).
fn xe_huc_query(version: Option<(u8, u8, u8)>) -> Result<(u32, u32, u32, u32), FsError> {
    let info = DeviceInfo {
        device_id: 0x7d55,
        platform: MTL,
        memory_bytes: 0x8000_0000,
        hwconfig: None,
        topology: None,
        vram: None,
        backend: Some(Arc::new(HucBackend(version))),
    };
    let file = RenderFile::new();
    let user = User::new();
    let mut wire = [0; 40];
    put32(&mut wire, 8, 7);
    put32(&mut wire, 12, 32);
    put64(&mut wire, 16, 1024);
    user.store(64, &wire);
    let mut data = [0; 32];
    data[..2].copy_from_slice(&1u16.to_le_bytes());
    data[4..20].fill(0xff); // outputs, overwritten on success
    user.store(1024, &data);
    let mut call = core::pin::pin!(file.dispatch_user(
        &info,
        crate::intel_gpu_xe_uapi::DEVICE_QUERY,
        64,
        &user
    ));
    match call.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Some(Ok(0))) => {
            let reply = user.load(1024, 32);
            Ok((
                u32_at(&reply, 4),
                u32_at(&reply, 8),
                u32_at(&reply, 12),
                u32_at(&reply, 16),
            ))
        }
        Poll::Ready(Some(Err(error))) => Err(error),
        other => panic!("HuC query {other:?}"),
    }
}

fn smoke_media_huc_guc_upload_auth_reload_and_xe_query() -> TestResult {
    MODE.store(0, Ordering::Relaxed);
    let image = huc_gsc();
    let load = huc::Load::media(&image).unwrap();
    assert_eq!(
        (load.css_offset, load.upload, load.rsa, load.version),
        (CSS_AT, UPLOAD, RSA, (8, 5, 4))
    );
    assert_eq!(load.object.len(), FILE, "uc_fw_copy copies the whole file");
    let firmware = huc::Firmware::from_fixture(MTL, &image).unwrap();
    let (w, arena) = media_model();
    let auths = AUTHS.load(Ordering::Relaxed);
    let mut guc = start(&w, &arena, Some((&firmware, false)));
    let mut hw = Hw::default();
    let mut dma = Vec::new();
    let (now, polled) = run(&mut guc, &w, &mut hw, 1, &mut dma, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert!(guc.publication().is_some());
    assert_eq!(AUTHS.load(Ordering::Relaxed), auths + 1);
    let base = huc_base(&w);
    // uc_fw_xfer through GT1's view: GGTT base + css_offset in GGTT space to
    // WOPCM offset 0, the CSS header plus uCode, with the GuC held in reset.
    assert_eq!(dma, [[base + CSS_AT, 0x80000, 0, 0x70000, UPLOAD, 1]]);
    {
        let d = w.0.borrow();
        let words = d.memory[&base].borrow();
        assert_eq!(words[0], CPD_MARKER);
        assert_eq!(words[(CSS_AT + 128) as usize / 4], 0x1234_5678);
        assert_eq!(words[FILE / 4], 0x0000_cdab, "tail dword zero-padded");
        // xe_wopcm_init: GuC base = ALIGN(upload + 16K, 16K) above the HuC,
        // the rest of MTL's 4 MiB less 36K, HUC_LOADING_AGENT_GUC.
        assert!(d.writes.contains(&(0x38c050, 0x3e_f000)));
        assert!(d.writes.contains(&(0x38c340, 0x8002)));
        assert!(d.writes.iter().all(|(reg, _)| gt1_owned(*reg)));
        assert!(!d.regs.contains_key(&0xc1dc), "GT0 HuC status untouched");
        assert_eq!(d.regs[&0xa188], 1, "GT0 wake untouched");
    }
    // xe_uc_load_hw: HuC DMA, its HUC_UKERNEL disable, then the submission
    // GuC load; xe_guc_min_load_for_hwconfig (the first boot) uploads none.
    let guc_dma = positions(&w, 0, (0x38c314, 0x0011_0011));
    let huc_dma = positions(&w, 0, (0x38c314, 0x0201_0201));
    let disable = positions(&w, 0, (0x38c314, 0x0200_0000));
    assert_eq!((guc_dma.len(), huc_dma.len(), disable.len()), (2, 1, 1));
    assert!(guc_dma[0] < huc_dma[0] && huc_dma[0] < disable[0] && disable[0] < guc_dma[1]);
    // RUNNING: the CSS release (not HUCP.man's) under GT1's current access.
    assert_eq!(guc.huc_outcome(), Some(true));
    assert_eq!(guc.huc_version(|| true), Some((8, 5, 4)));
    assert_eq!(guc.huc_version(|| false), None);
    // query_uc_fw_version: MEDIA_VER >= 13 reads the media GT's HuC; GT0
    // never answers, and without a media GT the query is ENODEV.
    assert_eq!(
        query_huc(MTL, Some(&guc), || true, || Some((7, 9, 3))),
        Some((8, 5, 4))
    );
    assert_eq!(
        query_huc::<Window, Arena>(MTL, None, || true, || Some((7, 9, 3))),
        None
    );
    assert_eq!(
        query_huc::<Window, Arena>(huc::PLATFORM, None, || true, || Some((7, 9, 3))),
        Some((7, 9, 3))
    );
    assert_eq!(xe_huc_query(Some((8, 5, 4))), Ok((0, 8, 5, 4)));
    assert_eq!(xe_huc_query(None), Err(FsError::NoDevice));
    // A cleared status bit is not RUNNING at query time.
    w.0.borrow_mut().regs.insert(MEDIA_HUC_STATUS, 0);
    assert_eq!(guc.huc_version(|| true), None);
    w.0.borrow_mut().regs.insert(MEDIA_HUC_STATUS, 1);
    // A verified stop (GuC reset, media GRDOM_FULL) reclaims the HuC too.
    stop(&mut guc, &w, &mut hw, now + 1);
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // Media-GT recovery: the HuC survived the GuC/GT reset and the WOPCM
    // stays locked. The next media GuC uploads it again (xe_uc_load_hw) and,
    // holding this owner's own authentication, adopts it (xe_huc_auth).
    reclaimed(&w, &arena);
    let from = w.0.borrow().writes.len();
    let mut guc = start(&w, &arena, Some((&firmware, true)));
    let mut hw = Hw::default();
    let mut dma = Vec::new();
    let (now, polled) = run(&mut guc, &w, &mut hw, 1, &mut dma, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert_eq!(dma.len(), 1);
    assert_eq!(AUTHS.load(Ordering::Relaxed), auths + 1, "no new request");
    assert!(
        positions(&w, from, (0x38c340, 0x8002)).is_empty(),
        "lock kept"
    );
    assert_eq!(guc.huc_outcome(), Some(true));
    assert_eq!(guc.huc_version(|| true), Some((8, 5, 4)));
    stop(&mut guc, &w, &mut hw, now + 1);
    drop(guc);

    // System resume: WOPCM and the HuC are lost; a fresh partition, upload
    // and authentication run even though adoption was allowed.
    reclaimed(&w, &arena);
    w.0.borrow_mut()
        .regs
        .extend([(MEDIA_HUC_STATUS, 0), (0x38c050, 0), (0x38c340, 0)]);
    let from = w.0.borrow().writes.len();
    let mut guc = start(&w, &arena, Some((&firmware, true)));
    let mut hw = Hw::default();
    let mut dma = Vec::new();
    let (now, polled) = run(&mut guc, &w, &mut hw, 1, &mut dma, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert_eq!(dma.len(), 1);
    assert_eq!(AUTHS.load(Ordering::Relaxed), auths + 2);
    assert_eq!(positions(&w, from, (0x38c340, 0x8002)).len(), 1);
    assert_eq!(guc.huc_version(|| true), Some((8, 5, 4)));
    stop(&mut guc, &w, &mut hw, now + 1);
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_huc_guc_upload_auth_reload_and_xe_query
);

fn smoke_media_huc_failures_keep_gt1_published() -> TestResult {
    let firmware = huc::Firmware::from_fixture(MTL, &huc_gsc()).unwrap();
    for case in 0..4 {
        let (w, arena) = media_model();
        match case {
            // xe_huc_auth: a failed AUTHENTICATE_HUC.
            0 => MODE.store(2, Ordering::Relaxed),
            // ACK without GT1's status bit within 100 ms; GT0's bit is not
            // the media HuC's.
            1 => {
                MODE.store(1, Ordering::Relaxed);
                w.0.borrow_mut().regs.insert(0xc1dc, 1);
            }
            // An authentication this owner never established.
            2 => {
                MODE.store(0, Ordering::Relaxed);
                w.0.borrow_mut().regs.insert(MEDIA_HUC_STATUS, 1);
            }
            // A locked WOPCM that names no HuC loading agent and leaves no
            // room below the GuC: the HuC is never uploaded.
            _ => {
                MODE.store(0, Ordering::Relaxed);
                w.0.borrow_mut()
                    .regs
                    .extend([(0x38c050, 0x3f_3001), (0x38c340, 0x4001)]);
            }
        }
        let auths = AUTHS.load(Ordering::Relaxed);
        let mut guc = start(&w, &arena, Some((&firmware, false)));
        let mut hw = Hw::default();
        let mut dma = Vec::new();
        let (now, polled) = run(&mut guc, &w, &mut hw, 1, &mut dma, |p| p.is_ready());
        assert_eq!(
            polled,
            Poll::Ready(Ok(MediaGucState::Running)),
            "HuC failure never fails GT1"
        );
        assert!(guc.publication().is_some());
        assert_eq!(guc.huc_outcome(), Some(false));
        assert_eq!(guc.huc_version(|| true), None);
        assert_eq!(
            query_huc(MTL, Some(&guc), || true, || Some((7, 9, 3))),
            None
        );
        assert_eq!(AUTHS.load(Ordering::Relaxed), auths + u32::from(case < 2));
        // Linux uploads even an authenticated HuC; a blocked one never.
        assert_eq!(dma.len(), usize::from(case < 3));
        if case == 3 {
            assert!(positions(&w, 0, (0x38c050, 0x3e_f000)).is_empty());
            assert!(!w.0.borrow().writes.iter().any(|(reg, _)| *reg == 0x38c340));
        }
        // The media engines keep working without HuC.
        let context = UserContext::for_engine(Engine::Vcs0);
        let (batch, result) = PpgttProbeResult::prepare(MTL).unwrap();
        let (_, fence) = guc
            .submit_user(now + 1, context, UserBatch(batch), None)
            .unwrap();
        let (now, _) = run(&mut guc, &w, &mut hw, now + 2, &mut dma, |_| {
            fence.result().is_some()
        });
        assert_eq!(fence.result(), Some(Ok(())));
        assert_eq!(result.verify(), Ok(()));
        stop(&mut guc, &w, &mut hw, now + 1);
        drop(guc);
        assert_eq!(arena.live_allocations(), 0);
        assert!(w.0.borrow().writes.iter().all(|(reg, _)| gt1_owned(*reg)));
    }
    MODE.store(0, Ordering::Relaxed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_huc_failures_keep_gt1_published
);

fn smoke_media_huc_option_staging_refusals_and_lost_status() -> TestResult {
    use crate::intel_gpu_guc_firmware::FirmwareError;
    use narf_boot::args::KernelCmdline;
    // Both default-off options, each in the shared pre-separator grammar,
    // on an MTL-classified device only.
    for (line, platform, wanted) in [
        ("narf.intel.huc=1 narf.intel.media_gt=1", Some(MTL), true),
        (
            "narf.intel.media_gt=1 quiet narf.intel.huc=1",
            Some(MTL),
            true,
        ),
        ("narf.intel.huc=1", Some(MTL), false),
        ("narf.intel.media_gt=1", Some(MTL), false),
        (
            "narf.intel.media_gt=1 -- narf.intel.huc=1",
            Some(MTL),
            false,
        ),
        ("narf.intel.media_gt=1 narf.intel.huc", Some(MTL), false),
        (
            "narf.intel.huc=1 narf.intel.huc=1 narf.intel.media_gt=1",
            Some(MTL),
            false,
        ),
        (
            "narf.intel.huc=1 narf.intel.media_gt=1",
            Some(huc::PLATFORM),
            false,
        ),
        ("narf.intel.huc=1 narf.intel.media_gt=1", None, false),
    ] {
        assert_eq!(
            huc::media_opted_in(platform, KernelCmdline::new(line)),
            wanted,
            "{line}"
        );
    }
    // xe_huc_init: the primary GT owns HuC only through graphics 12.55.
    let ip = crate::intel_gpu_gt::media::MediaIp::decode(MEDIA_GMD);
    assert!(huc::profile(huc::PLATFORM, GuCRole::Primary));
    assert!(!huc::profile(MTL, GuCRole::Primary));
    assert!(huc::profile(MTL, GuCRole::Media(ip)));
    assert!(!huc::profile(GtPlatform::Battlemage, GuCRole::Media(ip)));
    // Images per profile, including parse_headers' whole-file CSS fallback.
    let image = huc_gsc();
    let css = image[CSS_AT as usize..CSS_AT as usize + 400].to_vec();
    let fallback = huc::Load::media(&css).unwrap();
    assert_eq!(
        (fallback.css_offset, fallback.upload, fallback.rsa),
        (0, UPLOAD, UPLOAD)
    );
    assert!(huc::Firmware::from_fixture(MTL, &css).is_ok());
    assert!(huc::Firmware::from_fixture(huc::PLATFORM, &image).is_err());
    assert!(matches!(
        huc::Firmware::from_fixture(GtPlatform::Battlemage, &image),
        Err(FirmwareError::Unsupported)
    ));
    // A CPD without its huc_fw entry parses its own header as CSS (-EPROTO).
    let mut broken = image.clone();
    broken[44..56].fill(0);
    assert!(huc::Load::media(&broken).is_err());
    assert!(huc::Firmware::from_fixture(MTL, &broken).is_err());
    let (write, read) = narf_firmware::bootstrap_authority();
    write.revoke();
    assert!(matches!(
        huc::Firmware::open(MTL, &read),
        Err(FirmwareError::Revoked)
    ));
    assert!(matches!(
        huc::Firmware::open(GtPlatform::Battlemage, &read),
        Err(FirmwareError::Unsupported)
    ));

    // A TGL image never stages on the media GuC: nothing allocated/written.
    let tgl = huc::Firmware::from_fixture(huc::PLATFORM, &css).unwrap();
    let (w, arena) = media_model();
    let staged = GuCGt::stage_media(
        crate::intel_gpu_gt::media::MediaGsi::new(w.clone()),
        arena.clone(),
        &guc_firmware(),
        Some((&tgl, false)),
        media_config(),
        ip,
        media_policy(),
    );
    assert!(matches!(
        staged.err(),
        Some(GtError::Boot(BootError::Unsupported))
    ));
    assert_eq!(arena.live_allocations(), 0);
    assert!(w.0.borrow().writes.is_empty());

    // An unallocatable HuC object refuses the start before any MMIO write;
    // the runtime then starts GT1 exactly as with the HuC option off.
    let firmware = huc::Firmware::from_fixture(MTL, &image).unwrap();
    let (w, arena) = media_model();
    w.0.borrow_mut().fail_at = Some(4); // image, ADS, log, then the HuC
    let media = MediaGt::initialized_for_test(MTL, MEDIA_GMD, FUSE);
    assert!(matches!(
        MediaGuc::start(
            w.clone(),
            arena.clone(),
            &guc_firmware(),
            Some((&firmware, false)),
            media_config(),
            &media,
            0
        )
        .err(),
        Some(MediaGucError::Gt(GtError::Boot(BootError::Allocation(_))))
    ));
    assert_eq!(arena.live_allocations(), 0);
    assert!(w.0.borrow().writes.is_empty());
    // The refused start freed its image, ADS and log: like the real arena,
    // the next start reuses that GGTT range, where the CT model expects the
    // ADS.
    reclaimed(&w, &arena);
    let auths = AUTHS.load(Ordering::Relaxed);
    let mut guc = start(&w, &arena, None);
    let mut hw = Hw::default();
    let mut dma = Vec::new();
    let (now, polled) = run(&mut guc, &w, &mut hw, 1, &mut dma, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert!(dma.is_empty());
    assert!(w.0.borrow().writes.contains(&(0x38c050, 0x3f_3000)));
    assert!(w.0.borrow().writes.contains(&(0x38c340, 0x4000)));
    assert!(positions(&w, 0, (0x38c314, 0x0201_0201)).is_empty());
    assert_eq!(AUTHS.load(Ordering::Relaxed), auths);
    assert_eq!(guc.huc_outcome(), None);
    assert_eq!(guc.huc_version(|| true), None);
    assert_eq!(
        query_huc(MTL, Some(&guc), || true, || Some((7, 9, 3))),
        None
    );
    stop(&mut guc, &w, &mut hw, now + 1);
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // An all-ones HUC_KERNEL_LOAD_INFO before the request is lost GT1 MMIO,
    // never an authentication to adopt: GT1 is not published and stops.
    MODE.store(0, Ordering::Relaxed);
    let (w, arena) = media_model();
    w.0.borrow_mut().regs.insert(MEDIA_HUC_STATUS, u32::MAX);
    let mut guc = start(&w, &arena, Some((&firmware, true)));
    let mut hw = Hw::default();
    let mut dma = Vec::new();
    let (now, polled) = run(&mut guc, &w, &mut hw, 1, &mut dma, |p| p.is_ready());
    assert!(matches!(polled, Poll::Ready(Err(MediaGucError::Gt(_)))));
    assert_eq!(guc.publication(), None);
    assert_eq!(dma.len(), 1);
    assert_eq!(AUTHS.load(Ordering::Relaxed), auths);
    let (_, polled) = run(&mut guc, &w, &mut hw, now + 1, &mut dma, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_huc_option_staging_refusals_and_lost_status
);
