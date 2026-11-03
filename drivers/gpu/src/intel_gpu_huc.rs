//! HuC DMA upload and GuC authentication. Linux b90c984d: xe_huc.c,
//! xe_uc_fw.c, xe_wopcm.c and xe_guc.c. xe_huc.c::xe_huc_init places the HuC
//! on the primary GT through graphics 12.55 and on the media GT above it, so
//! NARF's two profiles are owned by different GuCs:
//! - exact TGL: the main GuC loads `i915/tgl_huc.bin` (whole-file CSS);
//! - MTL/Arrow: the standalone media GuC loads `i915/mtl_huc_gsc.bin`, whose
//!   GSC CPD headers embed the CSS that is DMA-uploaded (xe_uc_fw.c
//!   parse_headers), and authenticates it via XE_HUC_AUTH_VIA_GUC.
//!
//! Firmware authority is not authentication. The boot owner retains DMA; this
//! typed CT owner never receives independently.

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_gt::{media::gsc, Gen12Platform, GtPlatform},
    intel_gpu_guc::{GuCError, GuCMessage},
    intel_gpu_guc_boot::{BootAllocator, GuCRole},
    intel_gpu_guc_firmware::FirmwareError,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_uapi::u32_at,
};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

pub(crate) const PLATFORM: GtPlatform = GtPlatform::Gen12(Gen12Platform::TigerLake);
const NAME: &str = "i915/tgl_huc.bin";
const FIRST: u16 = 0x4000;
const LAST: u16 = 0x7eff; // log sideband starts at7f00; SLPC at8000
/// NARF bound on an acquired HuC file (Linux copies any size into its BO).
const MAX_FILE: usize = 4 * 1024 * 1024;

pub(crate) fn opted_in(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, "narf.intel.huc")
}

/// xe_huc.c::xe_huc_init: whether the GuC in `role` owns `platform`'s HuC.
/// Linux supports HuC on the primary GT only through graphics 12.55 and on
/// the media GT otherwise; NARF admits exact TGL and the MTL/Arrow media GT.
pub(crate) fn profile(platform: GtPlatform, role: GuCRole) -> bool {
    match role {
        GuCRole::Primary => platform == PLATFORM,
        GuCRole::Media(_) => crate::intel_gpu_gt::media::profile_eligible(platform),
    }
}

/// The MTL/Arrow media-GT HuC opt-in: `narf.intel.huc=1` on a device whose
/// media GT is itself admitted (`narf.intel.media_gt=1`).
pub(crate) fn media_opted_in(
    platform: Option<GtPlatform>,
    args: narf_boot::args::KernelCmdline<'_>,
) -> bool {
    crate::intel_gpu_gt::media::admitted(platform, args) && opted_in(args)
}

#[derive(Debug)]
pub(crate) struct Image<'a> {
    pub upload: &'a [u8],
    pub signature: &'a [u8],
    pub version: (u8, u8, u8),
    /// The whole file; `upload` and `signature` are its prefix.
    file: &'a [u8],
}
impl<'a> Image<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, GuCError> {
        if !(128..=MAX_FILE).contains(&bytes.len())
            || bytes.len() % 4 != 0
            || u32_at(bytes, 0) != 6
            || u32_at(bytes, 8) != 0x10000
            || u32_at(bytes, 16) != 0x8086
        {
            return Err(GuCError::FirmwareLayout);
        }
        let header = u32_at(bytes, 4) as usize;
        let total = u32_at(bytes, 24) as usize;
        let key = u32_at(bytes, 28) as usize;
        let modulus = u32_at(bytes, 32) as usize;
        let exponent = u32_at(bytes, 36) as usize;
        let non_css = key
            .checked_add(modulus)
            .and_then(|v| v.checked_add(exponent))
            .ok_or(GuCError::FirmwareLayout)?;
        if header.checked_sub(non_css) != Some(32) || total <= header || key == 0 {
            return Err(GuCError::FirmwareLayout);
        }
        let upload = (total - header)
            .checked_mul(4)
            .and_then(|v| v.checked_add(128))
            .ok_or(GuCError::FirmwareLayout)?;
        let end = key
            .checked_mul(4)
            .and_then(|v| upload.checked_add(v))
            .ok_or(GuCError::FirmwareLayout)?;
        let full = total.checked_mul(4).ok_or(GuCError::FirmwareLayout)?;
        if end > bytes.len() || (bytes.len() != end && bytes.len() != full) {
            return Err(GuCError::FirmwareLayout);
        }
        // HuC's reserved words are not GuC submission/private-data fields.
        // xe_uc_fw selects this unversioned asset with no minimum major.
        let v = u32_at(bytes, 64);
        Ok(Self {
            upload: &bytes[..upload],
            signature: &bytes[upload..end],
            version: ((v >> 16) as u8, (v >> 8) as u8, v as u8),
            file: bytes,
        })
    }
}

/// One staged HuC object and its DMA/RSA window: xe_uc_fw.c::uc_fw_copy
/// places the object at its GGTT base, uc_fw_xfer DMAs DMA_COPY_SIZE bytes
/// from `css_offset` and xe_huc_auth passes the base plus
/// xe_uc_fw_rsa_offset to the GuC.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Load<'a> {
    pub object: &'a [u8],
    /// uc_fw->css_offset: the DMA source within the object.
    pub css_offset: u32,
    /// sizeof(uc_css_header) + ucode_size: DMA_COPY_SIZE and the WOPCM HuC
    /// reservation (xe_uc_fw_get_upload_size).
    pub upload: u32,
    /// xe_uc_fw_rsa_offset: css_offset + upload.
    pub rsa: u32,
    /// versions.found[XE_UC_FW_VER_RELEASE] (the CSS sw_version).
    pub version: (u8, u8, u8),
}

impl<'a> From<Image<'a>> for Load<'a> {
    /// TGL stages the CSS header, uCode and RSA signature (not the optional
    /// modulus/exponent suffix), so its CSS starts the object.
    fn from(image: Image<'a>) -> Self {
        let upload = image.upload.len() as u32; // bounded by MAX_FILE
        Self {
            object: &image.file[..image.upload.len() + image.signature.len()],
            css_offset: 0,
            upload,
            rsa: upload,
            version: image.version,
        }
    }
}

impl<'a> Load<'a> {
    /// The MTL HuC as xe_uc_fw.c::parse_headers reads it: GSC CPD headers
    /// (HUCP.man, huc_fw) or, without a CPD marker, a whole-file CSS. The
    /// whole file is the object, as uc_fw_copy copies fw->data.
    pub(crate) fn media(bytes: &'a [u8]) -> Result<Self, gsc::GscError> {
        let huc = gsc::HucImage::parse(bytes)?;
        // parse_css_header bounds both extents by the blob, so neither the
        // DMA window nor the RSA leaves the object.
        let narrow = |value: usize| u32::try_from(value).map_err(|_| gsc::GscError::NoExec);
        Ok(Self {
            object: bytes,
            css_offset: narrow(huc.css_offset)?,
            upload: narrow(huc.dma_bytes())?,
            rsa: narrow(huc.rsa_offset())?,
            // CSS sw_version fields are 8 bits wide.
            version: (
                huc.release.major as u8,
                huc.release.minor as u8,
                huc.release.patch as u8,
            ),
        })
    }
}

fn validate(platform: GtPlatform, bytes: &[u8]) -> Result<Load<'_>, FirmwareError> {
    if platform == PLATFORM {
        Image::parse(bytes)
            .map(Load::from)
            .map_err(FirmwareError::Image)
    } else if crate::intel_gpu_gt::media::profile_eligible(platform) {
        if bytes.len() > MAX_FILE {
            return Err(FirmwareError::Image(GuCError::FirmwareLayout));
        }
        Load::media(bytes).map_err(|_| FirmwareError::Image(GuCError::FirmwareLayout))
    } else {
        Err(FirmwareError::Unsupported)
    }
}

#[derive(Debug)]
pub(crate) struct Firmware {
    bytes: Vec<u8>,
    platform: GtPlatform,
    _digest: [u8; 32],
    _signer: Option<[u8; 32]>,
}
struct Open(GtPlatform);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Firmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        // xe_uc_fw.c XE_HUC_FIRMWARE_DEFS: TIGERLAKE no_ver(i915, huc, tgl)
        // and METEORLAKE no_ver(i915, huc_gsc, mtl).
        let name = if self.0 == PLATFORM {
            NAME
        } else {
            gsc::HUC_FIRMWARE
        };
        let blob = match narf_firmware::open(name, cap) {
            Ok(b) => b,
            Err(e) => return Ok(Err(FirmwareError::Registry(e))),
        };
        blob.invoke(CopyImage(self.0))
    }
}
struct CopyImage(GtPlatform);
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<Firmware, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(FirmwareError::Registry)?;
            validate(self.0, view.bytes)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(Firmware {
                bytes,
                platform: self.0,
                _digest: view.sha256,
                _signer: view.signer,
            })
        })())
    }
}
impl Firmware {
    pub(crate) fn open(
        platform: GtPlatform,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        if platform != PLATFORM && !crate::intel_gpu_gt::media::profile_eligible(platform) {
            return Err(FirmwareError::Unsupported);
        }
        authority
            .invoke(Open(platform))
            .map_err(|_| FirmwareError::Revoked)?
    }
    /// An authorized-equivalent image for native fixtures.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn from_fixture(platform: GtPlatform, bytes: &[u8]) -> Result<Self, FirmwareError> {
        validate(platform, bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            platform,
            _digest: [0; 32],
            _signer: None,
        })
    }
    pub(crate) fn platform(&self) -> GtPlatform {
        self.platform
    }
    pub(crate) fn load(&self) -> Load<'_> {
        validate(self.platform, &self.bytes).expect("immutable authorized HuC image")
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct Upload {
    pub rsa: u32,
    pub version: (u8, u8, u8),
    /// xe_huc.c::xe_huc_auth reports a HuC that is already authenticated as
    /// RUNNING ("On newer platforms the HuC survives reset"). NARF adopts
    /// only an authentication it established itself for this image;
    /// otherwise a pre-set bit leaves the HuC unavailable.
    pub adopt: bool,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Off,
    Send,
    Reply,
    Status,
    Running,
    Unavailable,
}

pub(crate) struct Auth {
    phase: Phase,
    image: Option<Upload>,
    next: u16,
    pending: Option<u16>,
    deadline: u64,
    /// The pre-request authentication check has run.
    checked: bool,
}
impl Auth {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Off,
            image: None,
            next: FIRST,
            pending: None,
            deadline: 0,
            checked: false,
        }
    }
    pub(crate) fn started(&self) -> bool {
        self.phase != Phase::Off
    }
    pub(crate) fn done(&self) -> bool {
        matches!(self.phase, Phase::Running | Phase::Unavailable)
    }
    /// XE_UC_FIRMWARE_RUNNING reached; no MMIO.
    pub(crate) fn running(&self) -> bool {
        self.phase == Phase::Running
    }
    pub(crate) fn invalidate(&mut self) {
        self.phase = Phase::Unavailable;
        self.pending = None;
    }
    pub(crate) fn begin(&mut self, image: Upload, now: u64) {
        assert!(!self.started());
        self.image = Some(image);
        self.phase = Phase::Send;
        // Conservative total bound; Linux waits1s per attempt and retries50.
        self.deadline = now.saturating_add(1_000_000_000);
    }
    pub(crate) fn event(&mut self, m: &GuCMessage, now: u64) -> Result<bool, TransportError> {
        if !(FIRST..=LAST).contains(&m.fence) {
            return Ok(false);
        }
        if !self.started() || m.fence >= self.next {
            return Err(TransportError::Protocol(0x4000));
        }
        // Retired retry IDs never complete a later request or another owner.
        if self.pending != Some(m.fence) {
            return Ok(true);
        }
        // guc_ct_send_recv's wait_event_timeout reports a fence done when the
        // timeout expires as success (___wait_cond_timeout): a reply already
        // received is consumed even past the bound. progress() enforces the
        // bound only on a request that is still unanswered.
        if self.phase != Phase::Reply || !m.payload.is_empty() {
            return Err(TransportError::Protocol(0x4000));
        }
        match m.kind {
            3 => {} // BUSY never extends the deadline
            5 => {
                self.pending = None;
                self.phase = Phase::Send;
            }
            7 if m.auxiliary == 0 => {
                self.pending = None;
                self.phase = Phase::Status;
                self.deadline = now.saturating_add(gsc::AUTH_WAIT_NS);
            }
            6 | 7 => self.invalidate(), // xe_huc_auth rejects all nonzero DATA0
            _ => return Err(TransportError::Protocol(0x4000)),
        }
        Ok(true)
    }
    pub(crate) fn progress<M: MmioWindow, A: BootAllocator>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        now: u64,
    ) -> Result<(), TransportError> {
        if matches!(self.phase, Phase::Off | Phase::Running | Phase::Unavailable) {
            return Ok(());
        }
        let expired = now >= self.deadline;
        if self.phase == Phase::Status {
            // xe_huc_auth's xe_mmio_wait32 on HUC_KERNEL_LOAD_INFO reads once
            // more after its timeout: authentication seen by a late poll is
            // success; a bit still clear past the bound invalidates.
            match gsc::huc_authenticated(ct.window(), gsc::HucAuth::Guc) {
                None => return Err(TransportError::Unavailable),
                Some(true) => self.phase = Phase::Running,
                Some(false) if expired => self.invalidate(),
                Some(false) => {}
            }
            return Ok(());
        }
        // Replies were drained through event() before this poll. A request
        // still unanswered, or none issued, within the total bound needs a
        // full reset; no new request starts once it has passed.
        if expired {
            return Err(TransportError::Timeout);
        }
        if self.phase == Phase::Send {
            if !core::mem::replace(&mut self.checked, true) {
                // xe_huc.c::xe_huc_auth: xe_huc_is_authenticated before any
                // request, through this GuC's GT view (HUC_KERNEL_LOAD_INFO,
                // GSI-adjusted on the media GT).
                match gsc::huc_authenticated(ct.window(), gsc::HucAuth::Guc) {
                    None => return Err(TransportError::Unavailable),
                    Some(true) => {
                        if self.image.expect("owned HuC").adopt {
                            self.phase = Phase::Running;
                        } else {
                            self.invalidate();
                        }
                        return Ok(());
                    }
                    Some(false) => {}
                }
            }
            if self.next > LAST {
                return Err(TransportError::Protocol(0x4000));
            }
            let id = self.next;
            match ct.send(id, 0x4000, 0, &[self.image.expect("owned HuC").rsa], false) {
                Ok(()) => {
                    self.next += 1;
                    self.pending = Some(id);
                    self.phase = Phase::Reply;
                }
                Err(TransportError::Ct(GuCError::Full)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub(crate) fn version(&self, mmio: &impl MmioWindow) -> Option<(u8, u8, u8)> {
        if self.phase != Phase::Running {
            return None;
        }
        gsc::huc_authenticated(mmio, gsc::HucAuth::Guc)?
            .then(|| self.image.expect("authenticated HuC").version)
    }
}
