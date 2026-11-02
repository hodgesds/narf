//! Exact TGL main-GT HuC. Linux b90c984d: xe_huc.c, xe_uc_fw.c,
//! xe_wopcm.c and xe_guc.c. Firmware authority is not authentication.
//! The boot owner retains DMA; this typed CT owner never receives independently.

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_gt::{Gen12Platform, GtPlatform},
    intel_gpu_guc::{GuCError, GuCMessage},
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_uapi::u32_at,
};
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

pub(crate) const PLATFORM: GtPlatform = GtPlatform::Gen12(Gen12Platform::TigerLake);
const NAME: &str = "i915/tgl_huc.bin";
const FIRST: u16 = 0x4000;
const LAST: u16 = 0x7eff; // log sideband starts at7f00; SLPC at8000
const STATUS: u64 = 0xc1dc;

pub(crate) fn opted_in(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    let mut enabled = false;
    for token in args.tokens().take_while(|token| *token != "--") {
        if token == "narf.intel.huc" {
            return false;
        }
        if let Some(value) = token.strip_prefix("narf.intel.huc=") {
            if enabled || value != "1" {
                return false;
            }
            enabled = true;
        }
    }
    enabled
}

#[derive(Debug)]
pub(crate) struct Image<'a> {
    pub upload: &'a [u8],
    pub signature: &'a [u8],
    pub version: (u8, u8, u8),
}
impl<'a> Image<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, GuCError> {
        if !(128..=4 * 1024 * 1024).contains(&bytes.len())
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
        })
    }
}

#[derive(Debug)]
pub(crate) struct Firmware {
    bytes: Vec<u8>,
    _digest: [u8; 32],
    _signer: Option<[u8; 32]>,
}
struct Open;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for Open {
    type Output = Result<Firmware, crate::intel_gpu_guc_firmware::FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(NAME, cap) {
            Ok(b) => b,
            Err(e) => {
                return Ok(Err(crate::intel_gpu_guc_firmware::FirmwareError::Registry(
                    e,
                )))
            }
        };
        blob.invoke(CopyImage)
    }
}
struct CopyImage;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyImage {
    type Output = Result<Firmware, crate::intel_gpu_guc_firmware::FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        use crate::intel_gpu_guc_firmware::FirmwareError;
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(FirmwareError::Registry)?;
            Image::parse(view.bytes).map_err(FirmwareError::Image)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(Firmware {
                bytes,
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
    ) -> Result<Self, crate::intel_gpu_guc_firmware::FirmwareError> {
        use crate::intel_gpu_guc_firmware::FirmwareError;
        if platform != PLATFORM {
            return Err(FirmwareError::Unsupported);
        }
        authority.invoke(Open).map_err(|_| FirmwareError::Revoked)?
    }
    pub(crate) fn image(&self) -> Image<'_> {
        Image::parse(&self.bytes).expect("immutable authorized HuC image")
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct Upload {
    pub rsa: u32,
    pub version: (u8, u8, u8),
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
}
impl Auth {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Off,
            image: None,
            next: FIRST,
            pending: None,
            deadline: 0,
        }
    }
    pub(crate) fn started(&self) -> bool {
        self.phase != Phase::Off
    }
    pub(crate) fn done(&self) -> bool {
        matches!(self.phase, Phase::Running | Phase::Unavailable)
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
        if now >= self.deadline {
            return Err(TransportError::Timeout);
        }
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
                self.deadline = now.saturating_add(100_000_000);
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
        if now >= self.deadline {
            if self.phase == Phase::Status {
                self.invalidate();
                return Ok(());
            }
            return Err(TransportError::Timeout); // unresolved request requires full reset
        }
        if self.phase == Phase::Send {
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
        } else if self.phase == Phase::Status {
            let status = ct.window().read32(STATUS);
            if status == u32::MAX {
                return Err(TransportError::Unavailable);
            }
            if status & 1 != 0 {
                self.phase = Phase::Running;
            }
        }
        Ok(())
    }
    pub(crate) fn version(&self, mmio: &impl MmioWindow) -> Option<(u8, u8, u8)> {
        if self.phase != Phase::Running {
            return None;
        }
        let status = mmio.read32(STATUS);
        (status != u32::MAX && status & 1 != 0)
            .then(|| self.image.expect("authenticated HuC").version)
    }
}
