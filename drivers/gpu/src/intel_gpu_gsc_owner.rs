//! The MTL/Arrow media GT's GSC in production, behind `narf.intel.media_gt=1`
//! and `narf.intel.gsc=1`. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! - xe_gsc.c::xe_gsc_init (the `i915/mtl_gsc_1.bin` fetch; MISSING or an
//!   image error leaves the GSC unavailable) and xe_hw_engine.c::
//!   check_gsc_availability (GSCCS0 only with available firmware);
//! - xe_gsc.c::xe_gsc_init_post_hwconfig: the 4 MiB stolen private object
//!   (`intel_gpu_stolen`'s device-lifetime GSC claim behind the fixed GGTT DM
//!   window) and the GSCCS0 kernel queue (`media::GscQueue`);
//! - xe_gsc_proxy.c::xe_gsc_proxy_init: a proxy channel only beside a bound
//!   CSME component (`load::register_csme_proxy`), else the tolerated ENODEV;
//! - xe_uc.c::xe_uc_load_hw -> xe_gsc_load_start after the media GuC loaded
//!   and the HuC authenticated via the GuC, on every GT1 start (probe, GT
//!   reset, resume), and xe_uc_stop_prepare -> xe_gsc_stop_prepare, which
//!   lets a running load finish before the GT stops.
//!
//! `struct xe_gsc` lives for the device: the status, compatibility version
//! and private object survive every GT0 incarnation here too. Only the
//! objects that live in a GT0 arena (the version-query packet, the HuC
//! packet and a proxy channel) belong to one media GuC: they are attached
//! when that GuC runs and freed after its verified stop, or retained with
//! it.
//!
//! NARF deviations, each fail-closed: an unplaceable or unmappable private
//! object is INIT_FAIL where Linux fails the probe; a stop that must not wait
//! (fault cleanup) interrupts a running load, which then is LOAD_FAIL (only
//! an FLR, which NARF never performs, would recover it).

use super::load::{csme_bound, with_csme, GscUc, Gsccs, HucGsc, HucStatus, LoadError, Status};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::media::{GscQueue, MediaGuc, MediaGucState, MediaWindow};
use crate::intel_gpu_guc_boot::BootAllocator;
use crate::intel_gpu_stolen::{Carve, Layout, StolenObject, CARVE_CHUNK_PTES, GSC_BYTES, PAGE};
use alloc::vec::Vec;
use core::task::Poll;

/// GSC_VER_PKT_SZ * 2 and PXP43_HUC_AUTH_INOUT_SIZE * 2: 8 KiB each.
const PACKET_PAGES: u32 = 2;
/// GSC_PROXY_CHANNEL_SIZE: 32 KiB in each direction.
const CHANNEL_PAGES: u32 = 16;

/// What the owner needs from the platform to place and reach the object.
pub(crate) trait DsmPort {
    type Cpu: MmioWindow;
    /// detect_bar2_integrated's layout and the number of CPU-aperture GGTT
    /// entries to survey; `None` without usable DSM or with lost access.
    fn layout(&self) -> Option<(Layout, u64)>;
    /// GGTT PTE `index`, both dwords.
    fn pte(&self, index: u64) -> u64;
    /// The page allocator may own this physical page.
    fn system_ram(&self, phys: u64) -> bool;
    /// The CPU's DSM window (BAR2).
    fn cpu(&self) -> Self::Cpu;
}

/// One media GuC's arena objects and HuC view.
struct Session<A: BootAllocator> {
    allocator: A,
    huc: HucGsc<A::Backing>,
}

/// A queue whose GuC is gone: every job fails at once.
struct Stopped;
impl Gsccs for Stopped {
    fn submit(&mut self, _: &[u32]) -> Result<(), LoadError> {
        Err(LoadError::NoDevice)
    }
    fn finished(&mut self) -> Option<Result<(), LoadError>> {
        Some(Err(LoadError::Io))
    }
}

/// The media GT's GSC for the device's lifetime.
pub(crate) struct GscOwner<A: BootAllocator, C: MmioWindow> {
    uc: GscUc<StolenObject<C>, A::Backing>,
    /// The survey toward the private object's claim (first GT1 start only).
    carve: Option<Carve>,
    /// The device-lifetime claim: the layout it was placed in and its range.
    claim: Option<(Layout, (u64, u64))>,
    session: Option<Session<A>>,
}

impl<A: BootAllocator + Clone, C: MmioWindow> GscOwner<A, C> {
    /// xe_gsc_init: `image` is the fetched `i915/mtl_gsc_1.bin`, or `None`
    /// when it could not be fetched (MISSING).
    pub(crate) fn new(image: Option<&[u8]>) -> Self {
        Self {
            uc: GscUc::init(image),
            carve: None,
            claim: None,
            session: None,
        }
    }

    /// xe_uc_fw_is_available: GSCCS0 exists only then. An INIT_FAIL (a
    /// failed probe in Linux) is never retried.
    pub(crate) fn available(&self) -> bool {
        self.uc.status().available() && !matches!(self.uc.status(), Status::InitFail(_))
    }

    pub(crate) fn status(&self) -> Status {
        self.uc.status()
    }

    /// The compatibility version queried after the last load.
    pub(crate) fn compatibility(&self) -> Option<super::Version> {
        self.uc.compatibility()
    }

    /// gsc_er_complete declared the device wedged.
    pub(crate) fn wedged(&self) -> bool {
        self.uc.wedged()
    }

    /// No GSC work is queued or running.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn idle(&self) -> bool {
        self.uc.idle()
    }

    /// The HuC as the GSC left it for the current media GuC: `Some(true)`
    /// authenticated via the GSC as well, `Some(false)` LOAD_FAIL.
    pub(crate) fn huc(&self) -> Option<bool> {
        let session = self.session.as_ref()?;
        match session.huc.status {
            HucStatus::Running => Some(true),
            HucStatus::LoadFail => Some(false),
            _ => None,
        }
    }

    /// Advance the GSC beside `guc` by bounded steps: on its first Running
    /// poll open this GuC's session (claim and DM-map the private object,
    /// attach the arena objects, xe_gsc_load_start), then run gsc_work.
    /// `mmio` is the device BAR; the worker sees it through GT1's GSI view.
    /// `events` are the decoded GSC interrupt causes (`GSC_EVENT_*`).
    /// `Ready` once no GSC work is queued.
    pub(crate) fn poll<M: MmioWindow + Clone, P: DsmPort<Cpu = C>>(
        &mut self,
        now: u64,
        guc: &mut MediaGuc<M, A>,
        mmio: &M,
        port: &P,
        huc_gsc_headers: bool,
        events: u32,
    ) -> Poll<()> {
        if !self.available() || guc.state() != MediaGucState::Running || !guc.gsccs_scheduled() {
            return Poll::Ready(());
        }
        let media = MediaWindow::new(mmio);
        if self.session.is_none() && self.open(guc, &media, port, huc_gsc_headers).is_pending() {
            return Poll::Pending;
        }
        let Some(session) = self.session.as_mut() else {
            return Poll::Ready(());
        };
        if events & crate::intel_gpu_gt_irq::GSC_EVENT_ER_COMPLETE != 0 {
            self.uc.er_complete_irq();
        }
        if events & crate::intel_gpu_gt_irq::GSC_EVENT_PROXY != 0 {
            self.uc.proxy_irq(csme_bound());
        }
        let before = session.huc.status;
        let uc = &mut self.uc;
        let polled = with_csme(|csme| {
            let mut queue = GscQueue::new(guc, now);
            uc.poll(now, &media, &mut queue, &mut session.huc, csme)
        });
        if before == HucStatus::Running && session.huc.status == HucStatus::LoadFail {
            guc.huc_gsc_failed();
        }
        polled
    }

    /// The private object's claim: a chunked aperture survey on the first
    /// GT1 start, the recorded range ever after.
    fn claim<P: DsmPort<Cpu = C>>(&mut self, port: &P) -> Poll<Option<(Layout, (u64, u64))>> {
        if let Some(claim) = self.claim {
            return Poll::Ready(Some(claim));
        }
        if self.carve.is_none() {
            match port.layout() {
                Some((layout, entries)) => self.carve = Some(Carve::new(layout, entries)),
                None => return Poll::Ready(None),
            }
        }
        let carve = self.carve.as_mut().expect("survey");
        match carve.place_gsc(|phys| port.system_ram(phys)) {
            None => {
                carve.survey(CARVE_CHUNK_PTES, |index| port.pte(index));
                Poll::Pending
            }
            Some(Ok(range)) => {
                let layout = carve.layout();
                self.carve = None;
                self.claim = Some((layout, range));
                Poll::Ready(self.claim)
            }
            Some(Err(_)) => {
                self.carve = None;
                Poll::Ready(None)
            }
        }
    }

    fn open<M: MmioWindow + Clone, P: DsmPort<Cpu = C>>(
        &mut self,
        guc: &mut MediaGuc<M, A>,
        media: &impl MmioWindow,
        port: &P,
        huc_gsc_headers: bool,
    ) -> Poll<()> {
        let first = !self.uc.private_attached();
        let claim = if first {
            match self.claim(port) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(claim) => claim,
            }
        } else {
            self.claim
        };
        let Some((layout, range)) = claim else {
            if first {
                // No private object: INIT_FAIL (Linux fails the MTL probe).
                let _ = self.uc.init_post_hwconfig(true, None, None);
            }
            return Poll::Ready(());
        };
        let mut allocator = guc.allocator();
        // Every incarnation rewrites the same DM PTEs (the GGTT may have
        // lost them across D3); the window and the range never move.
        let mapped = allocator.map_gsc_stolen(range.0, (GSC_BYTES / PAGE) as u32);
        if !first {
            // A refused rewrite leaves this media GuC without GSC work.
            return match mapped {
                Ok(_) => self.attach(guc, allocator, huc_gsc_headers, media),
                Err(_) => Poll::Ready(()),
            };
        }
        let private = mapped
            .ok()
            .and_then(|ggtt| StolenObject::gsc(port.cpu(), layout, range, ggtt));
        let Some(private) = private else {
            let _ = self.uc.init_post_hwconfig(true, None, None);
            return Poll::Ready(());
        };
        let Ok(packet) = allocator.alloc(PACKET_PAGES) else {
            let _ = self.uc.init_post_hwconfig(true, None, None);
            return Poll::Ready(());
        };
        if self
            .uc
            .init_post_hwconfig(true, Some(private), Some(packet))
            .is_err()
        {
            return Poll::Ready(());
        }
        // xe_gsc_proxy_init: without a CSME component this is the
        // tolerated ENODEV and no channel is allocated.
        let channel = if csme_bound() {
            allocator.alloc(CHANNEL_PAGES).ok()
        } else {
            None
        };
        let _ = self.uc.add_proxy(channel);
        self.start(guc, allocator, huc_gsc_headers, media)
    }

    /// A later media GuC: attach its arena objects to the surviving GSC.
    fn attach<M: MmioWindow + Clone>(
        &mut self,
        guc: &mut MediaGuc<M, A>,
        mut allocator: A,
        huc_gsc_headers: bool,
        media: &impl MmioWindow,
    ) -> Poll<()> {
        let Ok(packet) = allocator.alloc(PACKET_PAGES) else {
            return Poll::Ready(());
        };
        let channel = if csme_bound() {
            allocator.alloc(CHANNEL_PAGES).ok()
        } else {
            None
        };
        if self.uc.attach(packet, channel).is_err() {
            return Poll::Ready(());
        }
        self.start(guc, allocator, huc_gsc_headers, media)
    }

    /// The HuC view of this media GuC, then xe_gsc_load_start.
    fn start<M: MmioWindow + Clone>(
        &mut self,
        guc: &mut MediaGuc<M, A>,
        mut allocator: A,
        huc_gsc_headers: bool,
        media: &impl MmioWindow,
    ) -> Poll<()> {
        let object = guc.huc_object();
        let status = match (object, guc.huc_outcome()) {
            (None, _) | (_, None) => HucStatus::NotLoadable,
            (Some(_), Some(true)) => HucStatus::Running,
            (Some(_), Some(false)) => HucStatus::LoadFail,
        };
        // xe_huc_init allocates huc->gsc_pkt only for a HuC with GSC headers.
        let packet = (huc_gsc_headers && status != HucStatus::NotLoadable)
            .then(|| allocator.alloc(PACKET_PAGES).ok())
            .flatten();
        self.session = Some(Session {
            allocator,
            huc: HucGsc {
                status,
                packet,
                object: object.unwrap_or((0, 0)),
            },
        });
        let _ = self.uc.load_start(media);
        Poll::Ready(())
    }

    /// xe_gsc_stop_prepare: one more bounded step of a running load before
    /// the media GuC stops. `true` once no GSC work runs. Without a running
    /// GuC every remaining job fails at once.
    pub(crate) fn quiesce<M: MmioWindow + Clone>(
        &mut self,
        now: u64,
        guc: Option<&mut MediaGuc<M, A>>,
        mmio: &M,
    ) -> bool {
        if self.uc.idle() {
            return true;
        }
        let Some(session) = self.session.as_mut() else {
            return true;
        };
        let media = MediaWindow::new(mmio);
        let uc = &mut self.uc;
        let polled = with_csme(|csme| match guc {
            Some(guc) => {
                let mut queue = GscQueue::new(guc, now);
                uc.poll(now, &media, &mut queue, &mut session.huc, csme)
            }
            None => uc.poll(now, &media, &mut Stopped, &mut session.huc, csme),
        });
        polled.is_ready()
    }

    /// The media GuC is stopping without waiting (fault cleanup): end any
    /// running load now (LOAD_FAIL) and release the worker's own wake.
    pub(crate) fn interrupt(&mut self, mmio: &impl MmioWindow) {
        self.uc.abort(&MediaWindow::new(mmio));
    }

    /// The media GuC of this session is gone. After its verified stop
    /// (`proven`) GSCCS0 can no longer reach the arena objects, so they are
    /// freed; otherwise they stay retained with the GuC's own memory.
    pub(crate) fn end_session(&mut self, mmio: &impl MmioWindow, proven: bool) {
        let Some(mut session) = self.session.take() else {
            return;
        };
        self.interrupt(mmio);
        let mut objects: Vec<A::Backing> = self.uc.detach().unwrap_or_default();
        objects.extend(session.huc.packet.take());
        for object in objects {
            if proven {
                session.allocator.free(object);
            } else {
                core::mem::forget(object);
            }
        }
    }
}

/// xe_uc_fw.c uc_fw_request for `i915/mtl_gsc_1.bin` through the trusted
/// firmware registry: the image bytes, or `None` when it cannot be fetched
/// (XE_UC_FIRMWARE_MISSING).
pub(crate) fn fetch_firmware() -> Option<Vec<u8>> {
    use narf_capabilities::{Cap, CapError, CapOp, Read};
    struct Open;
    impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
        type Output = Option<Vec<u8>>;
        fn execute(
            self,
            cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
        ) -> Result<Self::Output, CapError> {
            let Ok(blob) = narf_firmware::open(super::GSC_FIRMWARE, cap) else {
                return Ok(None);
            };
            blob.invoke(CopyImage)
        }
    }
    struct CopyImage;
    impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
        type Output = Option<Vec<u8>>;
        fn execute(
            self,
            cap: &Cap<narf_firmware::FirmwareBlob, Read>,
        ) -> Result<Self::Output, CapError> {
            let Ok(view) = narf_firmware::view_of(cap) else {
                return Ok(None);
            };
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(view.bytes.len()).is_err() {
                return Ok(None);
            }
            bytes.extend_from_slice(view.bytes);
            Ok(Some(bytes))
        }
    }
    narf_firmware::trusted_loader_authority()?
        .derive::<Read>()
        .ok()?
        .invoke(Open)
        .ok()
        .flatten()
}
