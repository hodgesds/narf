//! The MTL/Arrow GSC microcontroller on the media GT: firmware load over
//! GSCCS, HuC authentication through the GSC and the GSC proxy start, as
//! Linux's GSC worker runs them. MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! - xe_gsc.c::{xe_gsc_init,xe_gsc_init_post_hwconfig,xe_gsc_load_start,
//!   gsc_work,gsc_upload_and_init,gsc_upload,memcpy_fw,emit_gsc_upload,
//!   gsc_fw_is_loaded,gsc_fw_wait,query_compatibility_version,gsc_er_complete,
//!   xe_gsc_hwe_irq_handler};
//! - xe_gsc_submit.c::xe_gsc_pkt_submit_kernel (one kernel job on `gsc->q`,
//!   an HZ fence wait: 0 is -ETIME);
//! - xe_huc.c::{xe_huc_auth,huc_auth_via_gsccs} for XE_HUC_AUTH_VIA_GSC;
//! - xe_gsc_proxy.c::{xe_gsc_proxy_init,xe_gsc_proxy_start,
//!   xe_gsc_proxy_request_handler,xe_gsc_proxy_irq_handler,proxy_query,
//!   validate_proxy_header,xe_gsc_proxy_init_done} and
//!   abi/gsc_proxy_commands_abi.h;
//! - xe_force_wake.c XE_FW_GSC (FORCEWAKE_GSC / FORCEWAKE_ACK_GSC, 50 ms);
//! - xe_uc_fw_types.h `enum xe_uc_fw_status` and xe_uc_fw.h's predicates.
//!
//! The owner is generic over the three things only the platform can supply:
//! the GSC kernel queue on GSCCS0 (`Gsccs`), the 4 MiB GSC private object
//! (Linux: XE_BO_FLAG_STOLEN | XE_BO_FLAG_GGTT, `P`) and the CSME side of the
//! GSC proxy (`CsmeProxy`, the MEI GSC proxy component's send/recv). NARF has
//! none of them yet, so this owner is exercised only by native models.
//!
//! Without a CSME component Linux behaves exactly as a kernel built without
//! CONFIG_INTEL_MEI_GSC_PROXY: xe_gsc_proxy_init returns -ENODEV (tolerated),
//! the firmware still loads and authenticates the HuC, then
//! xe_gsc_proxy_start fails with -ENODEV and gsc_work records LOAD_FAIL, an
//! error state in which xe_gsc_load_start never reloads.
//!
//! NARF deviations, each fail-closed: an all-ones register read is lost MMIO
//! rather than a set bit; an unacknowledged GSC forcewake ends the work
//! (Linux proceeds without the wake); a GSCCS job that never retires blocks
//! later submissions (Linux queues behind it); a missing or malformed image
//! and an unavailable private object leave the GSC unavailable where Linux
//! fails the MTL probe.

use super::heci::{
    check_and_update_pending, compatibility_query, compatibility_reply, emit_header, fw_load,
    heci_packet, huc_auth_reply, huc_auth_request, read_out_header, GscImage, AUTH_ATTEMPTS,
    AUTH_RETRY_NS, HEADER, LOAD_WAIT_NS, PACKET_HALF, PRIVATE_BYTES,
};
use super::{huc_authenticated, GscError, HucAuth, Version, AUTH_WAIT_NS};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_rcs::GpuBacking;
use alloc::vec::Vec;
use core::task::Poll;

/// regs/xe_gsc_regs.h at the absolute MTL_GSC_HECI1/2 bases.
const HECI1_FWSTS1: u64 = 0x116000 + 0xc40;
const FWSTS1_CURRENT_STATE: u32 = 0xf;
const FWSTS1_PROXY_STATE_NORMAL: u32 = 5;
const FWSTS1_INIT_COMPLETE: u32 = 1 << 9;
const HECI2_H_CSR: u64 = super::HECI2_H_CSR;
const HECI_H_CSR_IE: u32 = 1 << 0;
const HECI_H_CSR_IS: u32 = 1 << 1;
const HECI_H_CSR_RST: u32 = super::HECI_H_CSR_RST;
const GSCI_TIMER_STATUS: u64 = 0x11ca28;
const GSCI_TIMER_EXPIRED: u32 = 1;
/// regs/xe_gt_regs.h FORCEWAKE_GSC / FORCEWAKE_ACK_GSC (GSI-adjusted on the
/// media GT) and the FORCEWAKE_KERNEL masked request.
const FORCEWAKE_GSC: u64 = 0xa618;
const FORCEWAKE_ACK_GSC: u64 = 0xdf8;
const KERNEL_WAKE: u32 = 0x0001_0001;
const KERNEL_SLEEP: u32 = 0x0001_0000;
const WAKE_NS: u64 = 50_000_000;
/// dma_fence_wait_timeout(fence, false, HZ).
const JOB_NS: u64 = 1_000_000_000;
/// xe_gsc_proxy.c GSC_PROXY_INIT_TIMEOUT_MS, polled every 100 ms.
const BIND_NS: u64 = 20_000_000_000;
/// GSC_PROXY_BUFFER_SIZE: 32 KiB in each direction of the proxy channel.
pub(crate) const PROXY_BUFFER: u32 = 32 * 1024;
const PROXY_HEADER: usize = 16;
const HECI_PROXY: u8 = 10;
const PROXY_QUERY: u32 = 1;
const PROXY_PAYLOAD: u32 = 2;
const PROXY_END: u32 = 3;
const ADDRESS_KMD: u32 = 0x10000;
const ADDRESS_GSC: u32 = 0x20000;
const ADDRESS_CSME: u32 = 0x30000;
/// include/linux/poison.h POISON_FREE (xe_gsc_poison_header).
const POISON: u8 = 0x6b;

/// gsc_work's action bits (xe_gsc_types.h).
const FW_LOAD: u32 = 1 << 0;
const SW_PROXY: u32 = 1 << 1;
const ER_COMPLETE: u32 = 1 << 2;

/// Failures of the load path, each with the errno its Linux branch returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// -EEXIST: gsc_upload found the GSC already loaded.
    Exists,
    /// -ETIME: a GSCCS kernel job did not finish within HZ.
    Time,
    /// -ETIMEDOUT: an xe_mmio_wait32 bound expired.
    TimedOut,
    /// -ENODEV: no GSCCS engine, no HuC packet object or no proxy component.
    NoDevice,
    /// -EBUSY: the GSC kept a HuC request pending through every retry.
    Busy,
    /// -EIO: GSC ER timed out, proxy init incomplete or a status error.
    Io,
    /// -EINVAL: a proxy message larger than its buffer.
    Invalid,
    /// -ENOEXEC: a proxy header with the wrong source or destination.
    NoExec,
    /// -E2BIG: a proxy payload that overflows its buffer.
    TooBig,
    /// -EPROTO: a CSME reply shorter than a proxy header.
    Protocol,
    /// A GSC header, packet or version refusal (its own errno).
    Packet(GscError),
    /// The CSME component's send/recv errno.
    Csme(i32),
    /// The GSC kernel queue refused a job while an earlier one is unretired.
    Queue,
    /// NARF: an all-ones register read (lost MMIO).
    Unavailable,
    /// NARF: FORCEWAKE_GSC was not acknowledged within 50 ms.
    Wake,
    /// No private object or version packet could be prepared.
    NoMemory,
}

impl GscError {
    /// The errno of the Linux branch this refusal mirrors.
    pub(crate) fn errno(self) -> i32 {
        match self {
            GscError::NotCpd => -2,
            GscError::Invalid => -22,
            GscError::NoData => -61,
            GscError::Protocol => -71,
            GscError::NoExec => -8,
            GscError::NoMemory => -12,
            GscError::Io => -5,
            GscError::TooLarge => -7,
        }
    }
}

impl LoadError {
    /// The errno Linux returns on this path (NARF-only refusals use the
    /// closest errno: lost MMIO and a lost wake are -EIO).
    pub(crate) fn errno(self) -> i32 {
        match self {
            LoadError::Exists => -17,
            LoadError::Time => -62,
            LoadError::TimedOut => -110,
            LoadError::NoDevice => -19,
            LoadError::Busy | LoadError::Queue => -16,
            LoadError::Io | LoadError::Unavailable | LoadError::Wake => -5,
            LoadError::Invalid => -22,
            LoadError::NoExec => -8,
            LoadError::TooBig => -7,
            LoadError::Protocol => -71,
            LoadError::Packet(error) => error.errno(),
            LoadError::Csme(errno) => errno,
            LoadError::NoMemory => -12,
        }
    }
}

/// `enum xe_uc_fw_status` as the GSC firmware reaches it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// An empty `gsc_firmware_path`: `narf.intel.gsc` is off.
    Disabled,
    /// The firmware file could not be fetched.
    Missing,
    /// The image failed parse_gsc_layout.
    Error(GscError),
    /// Fetched and parsed; the private object and queue are not ready.
    Available,
    /// NARF: xe_gsc_init_post_hwconfig could not complete (Linux fails probe).
    InitFail(LoadError),
    Loadable,
    LoadFail(LoadError),
    Transferred,
    Running,
}

impl Status {
    fn rank(self) -> u8 {
        match self {
            Status::Disabled => 1,
            Status::Missing => 3,
            Status::Error(_) => 4,
            Status::Available => 5,
            Status::InitFail(_) => 6,
            Status::Loadable => 7,
            Status::LoadFail(_) => 8,
            Status::Transferred => 9,
            Status::Running => 10,
        }
    }
    /// xe_uc_fw_is_available.
    pub(crate) fn available(self) -> bool {
        self.rank() >= Status::Available.rank()
    }
    /// xe_uc_fw_is_loadable (no PRELOADED state on a PF).
    pub(crate) fn loadable(self) -> bool {
        self.rank() >= Status::Loadable.rank()
    }
    /// xe_uc_fw_is_loaded.
    pub(crate) fn loaded(self) -> bool {
        self.rank() >= Status::Transferred.rank()
    }
    /// xe_uc_fw_is_in_error_state (xe_uc_fw_status_to_error < 0).
    pub(crate) fn error(self) -> bool {
        matches!(
            self,
            Status::Disabled
                | Status::Missing
                | Status::Error(_)
                | Status::InitFail(_)
                | Status::LoadFail(_)
        )
    }
}

/// `huc->fw.status` as xe_huc_auth(XE_HUC_AUTH_VIA_GSC) reads and writes it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HucStatus {
    /// No HuC image is staged (below XE_UC_FIRMWARE_LOADABLE).
    NotLoadable,
    Loadable,
    LoadFail,
    /// Authenticated (via the media GuC, or now via the GSC).
    Running,
}

/// The media GT's HuC as the GSC worker sees it.
#[derive(Debug)]
pub(crate) struct HucGsc<B> {
    pub(crate) status: HucStatus,
    /// huc->gsc_pkt: 8 KiB, allocated only for a HuC with GSC headers.
    pub(crate) packet: Option<B>,
    /// xe_bo_ggtt_addr(huc->fw.bo) and xe_bo_size(huc->fw.bo).
    pub(crate) object: (u64, u32),
}

/// The GSC kernel exec queue on GSCCS0 (`gsc->q`: EXEC_QUEUE_FLAG_KERNEL |
/// EXEC_QUEUE_FLAG_PERMANENT, no VM, GGTT addresses).
pub(crate) trait Gsccs {
    /// xe_bb_new + xe_bb_create_job + xe_sched_job_push of `commands`.
    fn submit(&mut self, commands: &[u32]) -> Result<(), LoadError>;
    /// The pushed job's finished fence: `None` while it runs.
    fn finished(&mut self) -> Option<Result<(), LoadError>>;
}

/// `struct i915_gsc_proxy_component_ops`
/// (include/drm/intel/i915_gsc_proxy_mei_interface.h): the MEI GSC proxy
/// client (drivers/misc/mei/gsc_proxy/mei_gsc_proxy.c, MEI client UUID
/// f73db04-97ab-4125-b893-e904ad0d5464) bound to the built-in display device.
pub(crate) trait CsmeProxy {
    /// ops->send (mei_cldev_send): bytes sent or a negative errno.
    fn send(&mut self, message: &[u8]) -> Result<usize, i32>;
    /// ops->recv (mei_cldev_recv) into `buffer`: bytes or a negative errno.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, i32>;
}

/// No CSME component: NARF has no MEI client interface.
pub(crate) enum NoCsme {}
impl CsmeProxy for NoCsme {
    fn send(&mut self, _: &[u8]) -> Result<usize, i32> {
        match *self {}
    }
    fn recv(&mut self, _: &mut [u8]) -> Result<usize, i32> {
        match *self {}
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Step {
    Idle,
    /// XE_FW_GSC requested; waiting for its acknowledgement.
    Wake,
    /// emit_gsc_upload: GSC_FW_LOAD in flight.
    Upload,
    /// gsc_fw_wait: HECI1_FWSTS1 INIT_COMPLETE within 500 ms.
    Init,
    /// query_compatibility_version: the MKHI packet in flight.
    Query,
    /// huc_auth_via_gsccs: NEW_HUC_AUTH in flight.
    HucAuth,
    /// The GSC replied pending: 50 ms before the next submission.
    HucRetry,
    /// xe_huc_auth: HECI1_FWSTS5 HUC_AUTH_DONE within 100 ms.
    HucStatus,
    /// xe_gsc_proxy_request_handler: waiting for the component to bind.
    ProxyBind,
    /// proxy_query: a proxy packet in flight.
    Proxy,
}

/// The proxy channel: `to_gsc` at 0, `from_gsc` at 32 KiB of one GGTT
/// object, and the CPU-side CSME buffers.
#[derive(Debug)]
struct Proxy<B> {
    channel: B,
    to_csme: Vec<u8>,
    from_csme: Vec<u8>,
    /// Bytes of the message staged in `to_gsc`.
    size: u32,
}

/// `struct xe_gsc` of the media GT.
#[derive(Debug)]
pub(crate) struct GscUc<P, B> {
    status: Status,
    image: Option<(GscImage, Vec<u8>)>,
    private: Option<P>,
    packet: Option<B>,
    compatibility: Option<Version>,
    /// xe->needs_flr_on_fini: the GSC was handed its private object.
    retained: bool,
    proxy: Option<Proxy<B>>,
    /// gsc->proxy.started.
    started: bool,
    /// The GSC hit an unrecoverable ER timeout (xe_device_declare_wedged).
    wedged: bool,
    actions: u32,
    work: u32,
    step: Step,
    deadline: u64,
    /// Submissions huc_auth_via_gsccs may still make.
    attempts: u32,
    input: Vec<u8>,
    /// FORCEWAKE_GSC was requested by this owner and not yet released.
    woke: bool,
    /// The running proxy request is xe_gsc_proxy_start's, inside FW_LOAD.
    proxy_for_load: bool,
}

fn put_words(backing: &impl GpuBacking, at: u64, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let offset = at + index as u64 * 4;
        let mut word = backing.read32(offset).to_le_bytes();
        word[..chunk.len()].copy_from_slice(chunk);
        backing.write32(offset, u32::from_le_bytes(word));
    }
}

fn get_words(backing: &impl GpuBacking, at: u64, len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len.next_multiple_of(4));
    let mut offset = at;
    while bytes.len() < len {
        bytes.extend_from_slice(&backing.read32(offset).to_le_bytes());
        offset += 4;
    }
    bytes.truncate(len);
    bytes
}

fn read(mmio: &impl MmioWindow, reg: u64) -> Result<u32, LoadError> {
    let value = mmio.read32(reg);
    if value == u32::MAX {
        Err(LoadError::Unavailable)
    } else {
        Ok(value)
    }
}

/// xe_gsc.c::gsc_fw_is_loaded through the media GT's view.
pub(crate) fn firmware_loaded(mmio: &impl MmioWindow) -> Result<bool, LoadError> {
    Ok(read(mmio, HECI1_FWSTS1)? & FWSTS1_INIT_COMPLETE != 0)
}

/// xe_gsc_proxy.c::xe_gsc_proxy_init_done: CURRENT_STATE is PROXY NORMAL.
pub(crate) fn proxy_init_done(mmio: &impl MmioWindow) -> Result<bool, LoadError> {
    Ok(read(mmio, HECI1_FWSTS1)? & FWSTS1_CURRENT_STATE == FWSTS1_PROXY_STATE_NORMAL)
}

/// The fields of `struct xe_gsc_proxy_header`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProxyHeader {
    pub(crate) kind: u32,
    pub(crate) length: u32,
    pub(crate) source: u32,
    pub(crate) destination: u32,
    pub(crate) status: u32,
}

impl ProxyHeader {
    pub(crate) fn parse(bytes: &[u8]) -> Self {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("dword"));
        Self {
            kind: word(0) & 0xff,
            length: word(0) >> 16,
            source: word(4),
            destination: word(8),
            status: word(12),
        }
    }
}

/// xe_gsc_proxy.c::validate_proxy_header, in its check order.
pub(crate) fn validate_proxy_header(
    header: ProxyHeader,
    source: u32,
    destination: u32,
    max: u32,
) -> Result<(), LoadError> {
    if header.destination != destination || header.source != source {
        return Err(LoadError::NoExec);
    }
    if header.length + PROXY_HEADER as u32 > max {
        return Err(LoadError::TooBig);
    }
    if destination == ADDRESS_KMD && header.status != 0 {
        return Err(LoadError::Io);
    }
    match header.kind {
        PROXY_PAYLOAD if header.length > 0 => Ok(()),
        PROXY_PAYLOAD | 0 => Err(LoadError::Io),
        _ => Ok(()),
    }
}

impl<P: GpuBacking, B: GpuBacking> GscUc<P, B> {
    fn with_status(status: Status, image: Option<(GscImage, Vec<u8>)>) -> Self {
        Self {
            status,
            image,
            private: None,
            packet: None,
            compatibility: None,
            retained: false,
            proxy: None,
            started: false,
            wedged: false,
            actions: 0,
            work: 0,
            step: Step::Idle,
            deadline: 0,
            attempts: 0,
            input: Vec::new(),
            woke: false,
            proxy_for_load: false,
        }
    }

    /// An empty `gsc_firmware_path` (`narf.intel.gsc` off).
    pub(crate) fn disabled() -> Self {
        Self::with_status(Status::Disabled, None)
    }

    /// xe_gsc_init on the media GT: `fetched` is the `i915/mtl_gsc_1.bin`
    /// image, or `None` when it could not be fetched (MISSING). The GSC
    /// compatibility version is only known after load (uc_fw_request skips
    /// the version check for GSC firmware).
    pub(crate) fn init(fetched: Option<&[u8]>) -> Self {
        let Some(bytes) = fetched else {
            return Self::with_status(Status::Missing, None);
        };
        match GscImage::parse(bytes) {
            Ok(image) => {
                let mut copy = Vec::new();
                if copy.try_reserve_exact(bytes.len()).is_err() {
                    return Self::with_status(Status::Error(GscError::NoMemory), None);
                }
                copy.extend_from_slice(bytes);
                Self::with_status(Status::Available, Some((image, copy)))
            }
            Err(error) => Self::with_status(Status::Error(error), None),
        }
    }

    /// xe_gsc_proxy_init: a CSME component can be added only beside a proxy
    /// channel (one 64 KiB GGTT object). Without one this is Linux's
    /// tolerated -ENODEV, and every later proxy request is -ENODEV.
    pub(crate) fn add_proxy(&mut self, channel: Option<B>) -> Result<(), LoadError> {
        if !self.status.available() {
            return Ok(());
        }
        let Some(channel) = channel else {
            return Err(LoadError::NoDevice);
        };
        if channel.size_pages() * 4096 < 2 * PROXY_BUFFER {
            return Err(LoadError::NoMemory);
        }
        let mut to_csme = Vec::new();
        let mut from_csme = Vec::new();
        if to_csme.try_reserve_exact(PROXY_BUFFER as usize).is_err()
            || from_csme.try_reserve_exact(PROXY_BUFFER as usize).is_err()
        {
            return Err(LoadError::NoMemory);
        }
        to_csme.resize(PROXY_BUFFER as usize, 0);
        from_csme.resize(PROXY_BUFFER as usize, 0);
        self.proxy = Some(Proxy {
            channel,
            to_csme,
            from_csme,
            size: 0,
        });
        Ok(())
    }

    /// xe_gsc_init_post_hwconfig: GSCCS0 must exist, and the 4 MiB private
    /// object (Linux: stolen, GGTT-mapped) and the 8 KiB version-query packet
    /// object must be ready. Linux fails the probe on any refusal; NARF
    /// records INIT_FAIL and the media GT continues without the GSC.
    pub(crate) fn init_post_hwconfig(
        &mut self,
        gsccs: bool,
        private: Option<P>,
        packet: Option<B>,
    ) -> Result<(), LoadError> {
        if !self.status.available() {
            return Ok(());
        }
        let result = if !gsccs {
            Err(LoadError::NoDevice)
        } else {
            match (private, packet) {
                (Some(private), Some(packet))
                    if private.size_pages() as usize * 4096 == PRIVATE_BYTES
                        && packet.size_pages() * 4096 >= 2 * PACKET_HALF =>
                {
                    self.private = Some(private);
                    self.packet = Some(packet);
                    Ok(())
                }
                _ => Err(LoadError::NoMemory),
            }
        };
        self.status = match result {
            Ok(()) => Status::Loadable,
            Err(error) => Status::InitFail(error),
        };
        result
    }

    pub(crate) fn status(&self) -> Status {
        self.status
    }

    /// versions.found[XE_UC_FW_VER_COMPATIBILITY] once queried.
    pub(crate) fn compatibility(&self) -> Option<Version> {
        self.compatibility
    }

    /// The RBEP.man release and security version of the parsed image.
    pub(crate) fn release(&self) -> Option<(Version, u32)> {
        self.image
            .as_ref()
            .map(|(image, _)| (image.release, image.security_version))
    }

    /// The GSC was handed its private object (xe->needs_flr_on_fini): it may
    /// use that memory until an FLR, so neither the object nor its GGTT
    /// range may ever be released or reused.
    pub(crate) fn private_retained(&self) -> bool {
        self.retained
    }

    /// gsc->proxy.started.
    pub(crate) fn proxy_started(&self) -> bool {
        self.started
    }

    /// gsc_er_complete found the GSC ER timer expired: the device is
    /// declared wedged (Linux has no FLR recovery here either).
    pub(crate) fn wedged(&self) -> bool {
        self.wedged
    }

    /// No work is queued or running.
    pub(crate) fn idle(&self) -> bool {
        self.step == Step::Idle && self.actions == 0
    }

    /// xe_gsc_load_start, after the media GuC loaded and the HuC was
    /// authenticated via the GuC (xe_uc_load_hw): at probe, after every GT
    /// reset and after resume. GSC firmware survives GT reset and D3hot, so
    /// a still-loaded GSC is only re-classified; an error state never
    /// reloads (only an FLR or D3cold resets the GSC).
    pub(crate) fn load_start(&mut self, mmio: &impl MmioWindow) -> Result<(), LoadError> {
        if !self.status.loadable() || self.private.is_none() || self.status.error() {
            return Ok(());
        }
        if firmware_loaded(mmio)? {
            self.status = if proxy_init_done(mmio)? {
                Status::Running
            } else {
                Status::Transferred
            };
            return Ok(());
        }
        self.actions |= FW_LOAD;
        Ok(())
    }

    /// xe_gsc_hwe_irq_handler: GSCCS reported GSC_ER_COMPLETE.
    pub(crate) fn er_complete_irq(&mut self) {
        self.actions |= ER_COMPLETE;
    }

    /// xe_gsc_proxy_irq_handler: the HECI2 interrupt asks for proxy work;
    /// it is dropped while no component is bound.
    pub(crate) fn proxy_irq(&mut self, bound: bool) {
        if bound {
            self.actions |= SW_PROXY;
        }
    }

    /// Drive gsc_work by bounded steps. `Ready` once no work is queued.
    pub(crate) fn poll<M: MmioWindow, Q: Gsccs, C: CsmeProxy>(
        &mut self,
        now: u64,
        mmio: &M,
        gsccs: &mut Q,
        huc: &mut HucGsc<B>,
        mut csme: Option<&mut C>,
    ) -> Poll<()> {
        loop {
            let progressed = match self.step {
                Step::Idle => {
                    if self.actions == 0 {
                        return Poll::Ready(());
                    }
                    self.begin_work(mmio, now);
                    true
                }
                Step::Wake => self.woken(mmio, now, gsccs, huc),
                Step::Upload => match self.job(now, gsccs) {
                    None => false,
                    Some(Ok(())) => {
                        self.deadline = now.saturating_add(LOAD_WAIT_NS);
                        self.step = Step::Init;
                        true
                    }
                    Some(Err(error)) => self.complete_load(Err(error), mmio, now),
                },
                Step::Init => self.initialized(mmio, now, gsccs),
                Step::Query => match self.job(now, gsccs) {
                    None => false,
                    Some(Ok(())) => self.queried(mmio, now, gsccs, huc),
                    Some(Err(error)) => self.complete_load(Err(error), mmio, now),
                },
                Step::HucAuth => match self.job(now, gsccs) {
                    None => false,
                    Some(Ok(())) => self.huc_replied(mmio, now, huc),
                    Some(Err(error)) => self.huc_done(Err(error), mmio, now, huc),
                },
                Step::HucRetry if now < self.deadline => false,
                Step::HucRetry if self.attempts == 0 => {
                    self.huc_done(Err(LoadError::Busy), mmio, now, huc)
                }
                Step::HucRetry => self.submit_huc(mmio, now, gsccs, huc),
                Step::HucStatus => match huc_authenticated(mmio, HucAuth::Gsc) {
                    None => self.huc_done(Err(LoadError::Unavailable), mmio, now, huc),
                    Some(true) => self.huc_done(Ok(()), mmio, now, huc),
                    Some(false) if now >= self.deadline => {
                        self.huc_done(Err(LoadError::TimedOut), mmio, now, huc)
                    }
                    Some(false) => false,
                },
                Step::ProxyBind => match csme.is_some() {
                    true => self.proxy_bound(mmio, now, gsccs),
                    false if now >= self.deadline => self.proxy_done(Err(LoadError::Io), mmio, now),
                    false => false,
                },
                Step::Proxy => match self.job(now, gsccs) {
                    None => false,
                    Some(result) => {
                        let reply = result.and_then(|()| match csme.as_deref_mut() {
                            Some(csme) => self.proxy_replied(csme),
                            None => Err(LoadError::Io),
                        });
                        match reply {
                            Ok(true) => self.proxy_done(Ok(()), mmio, now),
                            Ok(false) => self.proxy_send(mmio, now, gsccs),
                            Err(error) => self.proxy_done(Err(error), mmio, now),
                        }
                    }
                },
            };
            if !progressed {
                return Poll::Pending;
            }
        }
    }

    /// gsc_work: take the queued actions and request XE_FW_GSC.
    fn begin_work(&mut self, mmio: &impl MmioWindow, now: u64) {
        self.work = core::mem::take(&mut self.actions);
        self.proxy_for_load = false;
        match read(mmio, FORCEWAKE_GSC) {
            Ok(request) if request & 1 == 0 => {
                mmio.write32(FORCEWAKE_GSC, KERNEL_WAKE);
                self.woke = true;
                self.deadline = now.saturating_add(WAKE_NS);
                self.step = Step::Wake;
            }
            // Lost MMIO, or another agent holds the GSC wake request.
            Ok(_) => self.fail_work(LoadError::Wake, mmio),
            Err(error) => self.fail_work(error, mmio),
        }
    }

    /// The run ends before any action executed. A pending FW_LOAD becomes
    /// LOAD_FAIL, as gsc_work records any gsc_upload_and_init failure.
    fn fail_work(&mut self, error: LoadError, mmio: &impl MmioWindow) {
        if self.work & FW_LOAD != 0 {
            self.status = Status::LoadFail(error);
        }
        self.end_work(mmio);
    }

    fn woken<Q: Gsccs>(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        gsccs: &mut Q,
        huc: &mut HucGsc<B>,
    ) -> bool {
        match read(mmio, FORCEWAKE_ACK_GSC) {
            Err(error) => {
                self.fail_work(error, mmio);
                return true;
            }
            Ok(ack) if ack & 1 == 0 => {
                if now >= self.deadline {
                    self.fail_work(LoadError::Wake, mmio);
                    return true;
                }
                return false;
            }
            Ok(_) => {}
        }
        if self.work & ER_COMPLETE != 0 {
            // gsc_er_complete: a failure returns from gsc_work and drops the
            // run's other actions. Only a loaded GSC reports its ER timer.
            let expired = firmware_loaded(mmio).and_then(|loaded| {
                Ok(loaded && read(mmio, GSCI_TIMER_STATUS)? & 3 == GSCI_TIMER_EXPIRED)
            });
            match expired {
                Ok(false) => {}
                Ok(true) => {
                    self.wedged = true;
                    self.end_work(mmio);
                    return true;
                }
                Err(_) => {
                    self.end_work(mmio);
                    return true;
                }
            }
        }
        if self.work & FW_LOAD != 0 {
            return self.upload(mmio, now, gsccs, huc);
        }
        if self.work & SW_PROXY != 0 {
            return self.request_handler(mmio, now);
        }
        self.end_work(mmio);
        true
    }

    /// gsc_upload: refuse a loaded GSC (-EEXIST), copy the image into the
    /// private object (memcpy_fw zeroes the rest), then emit GSC_FW_LOAD.
    fn upload<Q: Gsccs>(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        gsccs: &mut Q,
        _huc: &mut HucGsc<B>,
    ) -> bool {
        match firmware_loaded(mmio) {
            Err(error) => return self.complete_load(Err(error), mmio, now),
            Ok(true) => return self.complete_load(Err(LoadError::Exists), mmio, now),
            Ok(false) => {}
        }
        let (Some(private), Some((_, bytes))) = (self.private.as_ref(), self.image.as_ref()) else {
            return self.complete_load(Err(LoadError::NoMemory), mmio, now);
        };
        let words = bytes.len().div_ceil(4);
        for index in 0..words {
            let mut word = [0u8; 4];
            let chunk = &bytes[index * 4..bytes.len().min(index * 4 + 4)];
            word[..chunk.len()].copy_from_slice(chunk);
            private.write32(index as u64 * 4, u32::from_le_bytes(word));
        }
        for index in words..PRIVATE_BYTES / 4 {
            private.write32(index as u64 * 4, 0);
        }
        // From here the GSC owns this memory, until an FLR.
        self.retained = true;
        let commands = fw_load(
            u64::from(private.ggtt_offset()),
            private.size_pages() as usize * 4096,
        );
        if let Err(error) = gsccs.submit(&commands) {
            return self.complete_load(Err(error), mmio, now);
        }
        self.deadline = now.saturating_add(JOB_NS);
        self.step = Step::Upload;
        true
    }

    /// The pushed job's fence, bounded by HZ (-ETIME).
    fn job<Q: Gsccs>(&mut self, now: u64, gsccs: &mut Q) -> Option<Result<(), LoadError>> {
        match gsccs.finished() {
            Some(result) => Some(result),
            None if now >= self.deadline => Some(Err(LoadError::Time)),
            None => None,
        }
    }

    /// gsc_fw_wait, then query_compatibility_version's packet.
    fn initialized<Q: Gsccs>(&mut self, mmio: &impl MmioWindow, now: u64, gsccs: &mut Q) -> bool {
        match firmware_loaded(mmio) {
            Err(error) => return self.complete_load(Err(error), mmio, now),
            Ok(false) if now >= self.deadline => {
                return self.complete_load(Err(LoadError::TimedOut), mmio, now);
            }
            Ok(false) => return false,
            Ok(true) => {}
        }
        let Some(packet) = self.packet.as_ref() else {
            return self.complete_load(Err(LoadError::NoMemory), mmio, now);
        };
        let mut input = alloc::vec![0u8; PACKET_HALF as usize];
        let submitted = compatibility_query(&mut input)
            .and_then(|size| {
                put_words(packet, 0, &input[..size as usize]);
                let address = u64::from(packet.ggtt_offset());
                heci_packet(address, size, address + u64::from(PACKET_HALF), PACKET_HALF)
            })
            .map_err(LoadError::Packet)
            .and_then(|batch| gsccs.submit(&batch));
        if let Err(error) = submitted {
            return self.complete_load(Err(error), mmio, now);
        }
        self.deadline = now.saturating_add(JOB_NS);
        self.step = Step::Query;
        true
    }

    /// The compatibility reply and xe_uc_fw_check_version_requirements, then
    /// TRANSFERRED and, for a HuC the media GuC authenticated, its
    /// authentication via the GSC (failure is not fatal to the GSC).
    fn queried<Q: Gsccs>(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        gsccs: &mut Q,
        huc: &mut HucGsc<B>,
    ) -> bool {
        let Some(packet) = self.packet.as_ref() else {
            return self.complete_load(Err(LoadError::NoMemory), mmio, now);
        };
        let reply = get_words(packet, u64::from(PACKET_HALF), PACKET_HALF as usize);
        let found = match compatibility_reply(&reply) {
            Ok(found) => found,
            Err(error) => return self.complete_load(Err(LoadError::Packet(error)), mmio, now),
        };
        self.compatibility = Some(found);
        if let Err(error) = super::heci::check_compatibility(found) {
            return self.complete_load(Err(LoadError::Packet(error)), mmio, now);
        }
        self.status = Status::Transferred;
        // xe_gt_sanitize_freq is a no-op here (Wa_22019338487 is media 20.00).
        match huc_authenticated(mmio, HucAuth::Guc) {
            None => self.complete_load(Err(LoadError::Unavailable), mmio, now),
            Some(false) => self.proxy_start(mmio, now),
            Some(true) => self.huc_auth(mmio, now, gsccs, huc),
        }
    }

    /// xe_huc_auth(huc, XE_HUC_AUTH_VIA_GSC) up to its first submission.
    fn huc_auth<Q: Gsccs>(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        gsccs: &mut Q,
        huc: &mut HucGsc<B>,
    ) -> bool {
        if huc.status == HucStatus::NotLoadable {
            return self.proxy_start(mmio, now);
        }
        match huc_authenticated(mmio, HucAuth::Gsc) {
            None => return self.huc_done(Err(LoadError::Unavailable), mmio, now, huc),
            // The HuC survives reset: already authenticated is RUNNING.
            Some(true) => return self.huc_done(Ok(()), mmio, now, huc),
            Some(false) => {}
        }
        if huc.status != HucStatus::Running {
            // xe_uc_fw_is_loaded is false: -ENOEXEC with no status change.
            return self.proxy_start(mmio, now);
        }
        if huc.packet.is_none() {
            // huc_auth_via_gsccs without huc->gsc_pkt.
            return self.huc_done(Err(LoadError::NoDevice), mmio, now, huc);
        }
        let mut input = alloc::vec![0u8; PACKET_HALF as usize];
        match huc_auth_request(&mut input, huc.object.0, huc.object.1) {
            Ok(size) => input.truncate(size as usize),
            Err(error) => return self.huc_done(Err(LoadError::Packet(error)), mmio, now, huc),
        }
        self.input = input;
        self.attempts = AUTH_ATTEMPTS;
        self.submit_huc(mmio, now, gsccs, huc)
    }

    /// One xe_gsc_pkt_submit_kernel of the staged NEW_HUC_AUTH input.
    fn submit_huc<Q: Gsccs>(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        gsccs: &mut Q,
        huc: &mut HucGsc<B>,
    ) -> bool {
        let Some(packet) = huc.packet.as_ref() else {
            return self.huc_done(Err(LoadError::NoDevice), mmio, now, huc);
        };
        put_words(packet, 0, &self.input);
        let address = u64::from(packet.ggtt_offset());
        let submitted = heci_packet(
            address,
            self.input.len() as u32,
            address + u64::from(PACKET_HALF),
            PACKET_HALF,
        )
        .map_err(LoadError::Packet)
        .and_then(|batch| gsccs.submit(&batch));
        if let Err(error) = submitted {
            return self.huc_done(Err(error), mmio, now, huc);
        }
        self.attempts -= 1;
        self.deadline = now.saturating_add(JOB_NS);
        self.step = Step::HucAuth;
        true
    }

    /// A pending reply hands its message handle back and retries after
    /// 50 ms (five submissions in all); otherwise the reply status decides
    /// and HUC_AUTH_DONE must appear within 100 ms.
    fn huc_replied(&mut self, mmio: &impl MmioWindow, now: u64, huc: &mut HucGsc<B>) -> bool {
        let Some(packet) = huc.packet.as_ref() else {
            return self.huc_done(Err(LoadError::NoDevice), mmio, now, huc);
        };
        let reply = get_words(packet, u64::from(PACKET_HALF), PACKET_HALF as usize);
        if check_and_update_pending(&mut self.input, &reply) {
            self.deadline = now.saturating_add(AUTH_RETRY_NS);
            self.step = Step::HucRetry;
            return true;
        }
        if let Err(error) = huc_auth_reply(&reply) {
            return self.huc_done(Err(LoadError::Packet(error)), mmio, now, huc);
        }
        self.deadline = now.saturating_add(AUTH_WAIT_NS);
        self.step = Step::HucStatus;
        true
    }

    /// xe_huc_auth's outcome: RUNNING, or LOAD_FAIL on any failure. The GSC
    /// load continues with the proxy start either way.
    fn huc_done(
        &mut self,
        result: Result<(), LoadError>,
        mmio: &impl MmioWindow,
        now: u64,
        huc: &mut HucGsc<B>,
    ) -> bool {
        huc.status = match result {
            Ok(()) => HucStatus::Running,
            Err(_) => HucStatus::LoadFail,
        };
        self.input.clear();
        self.proxy_start(mmio, now)
    }

    /// xe_gsc_proxy_start: enable the proxy interrupt in the GSC shim, then
    /// run the first request by hand.
    fn proxy_start(&mut self, mmio: &impl MmioWindow, now: u64) -> bool {
        self.proxy_for_load = true;
        if let Err(error) = irq_rmw(mmio, 0, HECI_H_CSR_IE) {
            return self.proxy_done(Err(error), mmio, now);
        }
        self.request_handler(mmio, now)
    }

    /// xe_gsc_proxy_request_handler: -ENODEV without a component, then up
    /// to 20 s for it to bind.
    fn request_handler(&mut self, mmio: &impl MmioWindow, now: u64) -> bool {
        if self.proxy.is_none() {
            return self.proxy_done(Err(LoadError::NoDevice), mmio, now);
        }
        self.deadline = now.saturating_add(BIND_NS);
        self.step = Step::ProxyBind;
        true
    }

    /// Bound: clear the pending interrupt and start proxy_query with a
    /// QUERY from the KMD to the GSC.
    fn proxy_bound<Q: Gsccs>(&mut self, mmio: &impl MmioWindow, now: u64, gsccs: &mut Q) -> bool {
        if let Err(error) = irq_rmw(mmio, 0, HECI_H_CSR_IS) {
            return self.proxy_done(Err(error), mmio, now);
        }
        let Some(proxy) = self.proxy.as_mut() else {
            return self.proxy_done(Err(LoadError::NoDevice), mmio, now);
        };
        let mut message = alloc::vec![0u8; HEADER + PROXY_HEADER];
        if let Err(error) = emit_header(&mut message, HECI_PROXY, 0, PROXY_HEADER as u32) {
            return self.proxy_done(Err(LoadError::Packet(error)), mmio, now);
        }
        message[HEADER..HEADER + 4].copy_from_slice(&PROXY_QUERY.to_le_bytes());
        message[HEADER + 4..HEADER + 8].copy_from_slice(&ADDRESS_KMD.to_le_bytes());
        message[HEADER + 8..HEADER + 12].copy_from_slice(&ADDRESS_GSC.to_le_bytes());
        put_words(&proxy.channel, 0, &message);
        proxy.size = message.len() as u32;
        self.proxy_send(mmio, now, gsccs)
    }

    /// Poison the reply header, then proxy_send_to_gsc.
    fn proxy_send<Q: Gsccs>(&mut self, mmio: &impl MmioWindow, now: u64, gsccs: &mut Q) -> bool {
        let Some(proxy) = self.proxy.as_mut() else {
            return self.proxy_done(Err(LoadError::NoDevice), mmio, now);
        };
        put_words(&proxy.channel, u64::from(PROXY_BUFFER), &[POISON; HEADER]);
        if proxy.size > PROXY_BUFFER {
            return self.proxy_done(Err(LoadError::Invalid), mmio, now);
        }
        let address = u64::from(proxy.channel.ggtt_offset());
        let submitted = heci_packet(
            address,
            proxy.size,
            address + u64::from(PROXY_BUFFER),
            PROXY_BUFFER,
        )
        .map_err(LoadError::Packet)
        .and_then(|batch| gsccs.submit(&batch));
        if let Err(error) = submitted {
            return self.proxy_done(Err(error), mmio, now);
        }
        self.deadline = now.saturating_add(JOB_NS);
        self.step = Step::Proxy;
        true
    }

    /// One proxy_query iteration after the GSC replied: `Ok(true)` for an
    /// END message, `Ok(false)` once the CSME reply is staged for the GSC.
    fn proxy_replied(&mut self, csme: &mut impl CsmeProxy) -> Result<bool, LoadError> {
        let proxy = self.proxy.as_mut().ok_or(LoadError::NoDevice)?;
        let reply = get_words(
            &proxy.channel,
            u64::from(PROXY_BUFFER),
            PROXY_BUFFER as usize,
        );
        let at = read_out_header(&reply, PROXY_HEADER as u32).map_err(LoadError::Packet)?;
        let header = ProxyHeader::parse(&reply[at..at + PROXY_HEADER]);
        let max = PROXY_BUFFER - at as u32;
        if header.kind == PROXY_END {
            validate_proxy_header(header, ADDRESS_GSC, ADDRESS_KMD, max)?;
            return Ok(true);
        }
        validate_proxy_header(header, ADDRESS_GSC, ADDRESS_CSME, max)?;
        let size = header.length as usize;
        proxy.to_csme[..PROXY_HEADER + size].copy_from_slice(&reply[at..at + PROXY_HEADER + size]);
        csme.send(&proxy.to_csme[..PROXY_HEADER + size])
            .map_err(LoadError::Csme)?;
        let size = csme
            .recv(&mut proxy.from_csme)
            .map_err(LoadError::Csme)?
            .min(PROXY_BUFFER as usize);
        if size < PROXY_HEADER {
            return Err(LoadError::Protocol);
        }
        validate_proxy_header(
            ProxyHeader::parse(&proxy.from_csme[..PROXY_HEADER]),
            ADDRESS_CSME,
            ADDRESS_GSC,
            max,
        )?;
        let mut message = alloc::vec![0u8; HEADER];
        emit_header(&mut message, HECI_PROXY, 0, size as u32).map_err(LoadError::Packet)?;
        message.extend_from_slice(&proxy.from_csme[..size]);
        put_words(&proxy.channel, 0, &message);
        proxy.size = message.len() as u32;
        Ok(false)
    }

    /// The end of a proxy request. Inside FW_LOAD this is
    /// xe_gsc_proxy_start's tail: proxy init must report done (else -EIO)
    /// and any failure disables the proxy interrupt again. A request from
    /// the HECI2 interrupt (SW_PROXY) only ends the run.
    fn proxy_done(
        &mut self,
        result: Result<(), LoadError>,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> bool {
        if !core::mem::take(&mut self.proxy_for_load) {
            self.work &= !SW_PROXY;
            self.end_work(mmio);
            return true;
        }
        let result = result.and_then(|()| match proxy_init_done(mmio)? {
            true => Ok(()),
            false => Err(LoadError::Io),
        });
        match result {
            Ok(()) => self.started = true,
            // err_irq_disable; lost MMIO cannot disable it.
            Err(_) => {
                let _ = irq_rmw(mmio, HECI_H_CSR_IE, 0);
            }
        }
        self.complete_load(result, mmio, now)
    }

    /// gsc_work after gsc_upload_and_init: LOAD_FAIL unless it succeeded or
    /// found the GSC already loaded (-EEXIST is RUNNING), then SW_PROXY.
    fn complete_load(
        &mut self,
        result: Result<(), LoadError>,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> bool {
        self.status = match result {
            Ok(()) | Err(LoadError::Exists) => Status::Running,
            Err(error) => Status::LoadFail(error),
        };
        self.work &= !FW_LOAD;
        if self.work & SW_PROXY != 0 {
            return self.request_handler(mmio, now);
        }
        self.end_work(mmio);
        true
    }

    /// Release XE_FW_GSC and return to idle.
    fn end_work(&mut self, mmio: &impl MmioWindow) {
        if core::mem::take(&mut self.woke) {
            mmio.write32(FORCEWAKE_GSC, KERNEL_SLEEP);
        }
        self.work = 0;
        self.proxy_for_load = false;
        self.step = Step::Idle;
    }
}

/// __gsc_proxy_irq_rmw on HECI2 H_CSR: never write the reset bit.
fn irq_rmw(mmio: &impl MmioWindow, clear: u32, set: u32) -> Result<(), LoadError> {
    let csr = read(mmio, HECI2_H_CSR)?;
    mmio.write32(HECI2_H_CSR, (csr & !(clear | HECI_H_CSR_RST)) | set);
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_gsc_load_tests.rs"]
mod tests;
