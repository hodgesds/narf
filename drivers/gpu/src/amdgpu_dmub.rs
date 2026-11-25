//! DCN 2.1 / 3.1.4 / 3.1.5 / 3.2.0 / 3.2.1 / 3.5.0 DMUB command transport. ABI
//! checked against Linux display/dmub/inc/dmub_cmd.h and
//! dmub_dcn20.c/dmub_dcn21.c/dmub_dcn31.c/dmub_dcn314.c/dmub_dcn32.c/dmub_dcn35.c.
//!
//! Attachment requires an already running DAL firmware and a mailbox wholly
//! inside the mapped VRAM aperture. This does not load firmware or reset DMCUB.
use crate::amdgpu::AmdGpu;
use core::sync::atomic::{fence, Ordering};
use narf_bus::MmioRegion;

use super::amdgpu_dmub_firmware as firmware;
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

/// One generation's DMCUB register map, as a DCN base-index-2 register
/// number table (`u32`, matching `Io::read`/`write` in
/// `amdgpu_dmub_boot`). DCN 2.0/2.1 and DCN 3.1.4 share the field
/// layout — CNTL ENABLE bit 16, SOFT_RESET bit 17, TRACEPORT_EN bit
/// 19, PWAIT bit 20 — but not the offsets, and DCN 2.0/2.1 has no
/// CNTL2: reset is CNTL's own SOFT_RESET bit. The 3.x table is the
/// current constants, byte-identical behavior; the 2.1 table is
/// `dcn_2_1_0_offset.h` (all BASE_IDX 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Regs {
    pub(crate) cntl: u32,
    /// DCN 3.x reset register; `None` on DCN 2.0/2.1 (see `SOFT_RESET`).
    pub(crate) cntl2: Option<u32>,
    pub(crate) hub_reset: u32,
    pub(crate) sec_cntl: u32,
    pub(crate) gpint: u32,
    pub(crate) status: u32,
    pub(crate) stop_reply: u32,
    pub(crate) fb_base: u32,
    pub(crate) fb_top: u32,
    pub(crate) fb_offset: u32,
    pub(crate) supported: u32,
    pub(crate) region5_offset: u32,
    pub(crate) region5_offset_high: u32,
    pub(crate) region5_top: u32,
    /// DCN 2.0/2.1 uncached-mailbox window; `None` on DCN 3.x.
    pub(crate) region4_offset: Option<u32>,
    pub(crate) region4_offset_high: Option<u32>,
    pub(crate) region4_top: Option<u32>,
    pub(crate) outbox0_base: u32,
    pub(crate) outbox0_size: u32,
    pub(crate) outbox0_wptr: u32,
    pub(crate) outbox0_rptr: u32,
    pub(crate) inbox1_base: u32,
    pub(crate) inbox1_size: u32,
    pub(crate) inbox1_wptr: u32,
    pub(crate) inbox1_rptr: u32,
    pub(crate) outbox1_base: u32,
    pub(crate) outbox1_size: u32,
    pub(crate) outbox1_wptr: u32,
    pub(crate) outbox1_rptr: u32,
    pub(crate) options: u32,
    pub(crate) psp_version: u32,
    pub(crate) cw_base: u32,
    pub(crate) cw_top: u32,
    pub(crate) cw_offset: u32,
    pub(crate) cw_offset_high: u32,
    /// Cache windows in this generation: 8 on DCN 3.x, 7 on DCN 2.0/2.1.
    pub(crate) cw_count: u32,
    /// Exclusive end of the DMCUB register bank, for bounds checks.
    pub(crate) bound: u32,
}
impl Regs {
    /// DCN 3.1.4 (`dcn_3_1_4_offset.h`); DCN 3.1.5 / 3.2.0 / 3.2.1
    /// share every offset this module reads.
    pub(crate) const DCN314: Self = Self {
        cntl: 0x1f6,
        cntl2: Some(0x200),
        hub_reset: 0x342,
        sec_cntl: 0x1ce,
        gpint: 0x1f8,
        status: 0x1e3,
        stop_reply: 0x1ea,
        fb_base: 0x475,
        fb_top: 0x476,
        fb_offset: 0x477,
        supported: 0xca,
        region5_offset: 0x198,
        region5_offset_high: 0x199,
        region5_top: 0x1a2,
        region4_offset: None,
        region4_offset_high: None,
        region4_top: None,
        outbox0_base: 0x1d8,
        outbox0_size: 0x1d9,
        outbox0_wptr: 0x1da,
        outbox0_rptr: 0x1db,
        inbox1_base: 0x1d4,
        inbox1_size: 0x1d5,
        inbox1_wptr: 0x1d6,
        inbox1_rptr: 0x1d7,
        outbox1_base: 0x1dc,
        outbox1_size: 0x1dd,
        outbox1_wptr: 0x1de,
        outbox1_rptr: 0x1df,
        options: 0x1f1,
        psp_version: 0x1f2,
        cw_base: 0x1a5,
        cw_top: 0x1ad,
        cw_offset: 0x1b5,
        cw_offset_high: 0x1b6,
        cw_count: 8,
        bound: 0x478,
    };
    /// DCN 3.5.0 (`dcn_3_5_0_offset.h`): every offset this module reads
    /// sits at the same offset as in `dcn_3_1_4_offset.h` — only the
    /// Loader's hub-reset register moved, 0x342 → 0x341
    /// (`MMHUBBUB_SOFT_RESET`).
    pub(crate) const DCN35: Self = Self {
        cntl: 0x1f6,
        cntl2: Some(0x200),
        hub_reset: 0x341,
        sec_cntl: 0x1ce,
        gpint: 0x1f8,
        status: 0x1e3,
        stop_reply: 0x1ea,
        fb_base: 0x475,
        fb_top: 0x476,
        fb_offset: 0x477,
        supported: 0xca,
        region5_offset: 0x198,
        region5_offset_high: 0x199,
        region5_top: 0x1a2,
        region4_offset: None,
        region4_offset_high: None,
        region4_top: None,
        outbox0_base: 0x1d8,
        outbox0_size: 0x1d9,
        outbox0_wptr: 0x1da,
        outbox0_rptr: 0x1db,
        inbox1_base: 0x1d4,
        inbox1_size: 0x1d5,
        inbox1_wptr: 0x1d6,
        inbox1_rptr: 0x1d7,
        outbox1_base: 0x1dc,
        outbox1_size: 0x1dd,
        outbox1_wptr: 0x1de,
        outbox1_rptr: 0x1df,
        options: 0x1f1,
        psp_version: 0x1f2,
        cw_base: 0x1a5,
        cw_top: 0x1ad,
        cw_offset: 0x1b5,
        cw_offset_high: 0x1b6,
        cw_count: 8,
        bound: 0x478,
    };
    /// DCN 2.1 (`dcn_2_1_0_offset.h`, all BASE_IDX 2). `dmub_dcn21.c`
    /// is a 56-line register table over DCN 2.0's functions, and
    /// `dmub_srv_hw_setup` gives DCN20/21 the same `dmub_srv_dcn20`
    /// functions with only the register table swapped, so this table
    /// serves Renoir and Cezanne alike.
    pub(crate) const DCN21: Self = Self {
        cntl: 0x32a0,
        cntl2: None,
        hub_reset: 0x0343,
        sec_cntl: 0x3278,
        gpint: 0x32a2,
        status: 0x328d,
        stop_reply: 0x3294,
        fb_base: 0x493,
        fb_top: 0x494,
        fb_offset: 0x495,
        supported: 0xca,
        region5_offset: 0x3242,
        region5_offset_high: 0x3243,
        region5_top: 0x324c,
        region4_offset: Some(0x3240),
        region4_offset_high: Some(0x3241),
        region4_top: Some(0x324b),
        outbox0_base: 0x3282,
        outbox0_size: 0x3283,
        outbox0_wptr: 0x3284,
        outbox0_rptr: 0x3285,
        inbox1_base: 0x327e,
        inbox1_size: 0x327f,
        inbox1_wptr: 0x3280,
        inbox1_rptr: 0x3281,
        outbox1_base: 0x3286,
        outbox1_size: 0x3287,
        outbox1_wptr: 0x3288,
        outbox1_rptr: 0x3289,
        options: 0x329b,
        psp_version: 0x329c,
        cw_base: 0x324f,
        cw_top: 0x3257,
        cw_offset: 0x325f,
        cw_offset_high: 0x3260,
        cw_count: 7,
        bound: 0x496,
    };
    pub(crate) fn for_version(version: (u8, u8, u8)) -> Option<Self> {
        match version {
            (2, 1, 0) => Some(Self::DCN21),
            (3, 1, 4) | (3, 1, 5) | (3, 2, 0) | (3, 2, 1) => Some(Self::DCN314),
            (3, 5, 0) => Some(Self::DCN35),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    Unsupported,
    VbiosUnavailable,
    Registry(narf_firmware::FirmwareError),
    Image(firmware::Error),
}

/// An immutable copy read through firmware capabilities. Holding it does not mean
/// the GPU is running the image; only the eventual boot handshake can do that.
#[derive(Debug)]
pub struct Firmware {
    bytes: Vec<u8>,
}

struct OpenFirmware(&'static str);
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenFirmware {
    type Output = Result<Vec<u8>, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(self.0, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(FirmwareError::Registry(error))),
        };
        blob.invoke(CopyFirmware)
    }
}
struct CopyFirmware;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyFirmware {
    type Output = Result<Vec<u8>, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(FirmwareError::Registry)?;
            // Validate sizes before allocating; no borrowed registry slice
            // escapes the capability invocation into later staging work.
            firmware::Image::parse(view.bytes).map_err(FirmwareError::Image)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::Registry(narf_firmware::FirmwareError::OutOfMemory))?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
impl Firmware {
    /// Prepare against the immutable platform image captured for this GPU.
    /// No ROM access or GPU writes are performed by preparation.
    pub fn prepare_from_gpu<'a>(
        &'a self,
        gpu: &'a AmdGpu,
    ) -> Result<firmware::Prepared<'a>, FirmwareError> {
        let ip = dmub_ip(gpu).map_err(|_| FirmwareError::Unsupported)?;
        let vbios = gpu.vbios.as_ref().ok_or(FirmwareError::VbiosUnavailable)?;
        match (ip.major, ip.minor, ip.revision) {
            (2, 1, 0) => self.prepare_dcn21(vbios.bytes()),
            (3, 2, 0) | (3, 2, 1) => self.prepare_dcn32(vbios.bytes()),
            (3, 5, 0) => self.prepare_dcn35(vbios.bytes()),
            _ => self.prepare(vbios.bytes()),
        }
    }
    /// Choose firmware from exact IP discovery, independently of the coarse
    /// PCI family table. DCN 3.5 requires a different hardware boot sequence.
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        let ip = dmub_ip(gpu).map_err(|_| FirmwareError::Unsupported)?;
        let name = match (ip.major, ip.minor, ip.revision) {
            (2, 1, 0) => {
                // The DMCUB blob is named per APU, not per DCN version:
                // Renoir (MP0 11.0.3) takes renoir_dmcub.bin, Cezanne
                // (MP0 12.0.1) takes green_sardine_dmcub.bin.
                match crate::amdgpu_discovery::find_ip(
                    &gpu.ip_blocks,
                    crate::amdgpu_discovery::HW_ID_MP0,
                    0,
                )
                .map(|mp0| (mp0.major, mp0.minor, mp0.revision))
                {
                    Some((11, 0, 3)) => firmware::DCN21_RENOIR_FIRMWARE,
                    Some((12, 0, 1)) => firmware::DCN21_GREEN_SARDINE_FIRMWARE,
                    _ => return Err(FirmwareError::Unsupported),
                }
            }
            (3, 1, 5) => firmware::DCN315_FIRMWARE,
            (3, 2, 0) => firmware::DCN320_FIRMWARE,
            (3, 2, 1) => firmware::DCN321_FIRMWARE,
            (3, 5, 0) => firmware::DCN35_FIRMWARE,
            _ => firmware::DCN314_FIRMWARE,
        };
        let bytes = authority.invoke(OpenFirmware(name)).map_err(|_| {
            FirmwareError::Registry(narf_firmware::FirmwareError::AuthorityRevoked)
        })??;
        Ok(Self { bytes })
    }
    /// Borrow the validated copy, without retaining a registry memory view.
    /// This is data already read, not authority to replace running firmware.
    pub fn image(&self) -> Result<firmware::Image<'_>, FirmwareError> {
        firmware::Image::parse(&self.bytes).map_err(FirmwareError::Image)
    }
    pub fn prepare<'a>(&'a self, vbios: &'a [u8]) -> Result<firmware::Prepared<'a>, FirmwareError> {
        self.image()?
            .prepare_dcn314(vbios)
            .map_err(FirmwareError::Image)
    }
    /// Prepare a DCN 3.2 image (combined layout, as for 3.1.4 — see
    /// [`firmware::Image::prepare_dcn32`]). Callers select by the
    /// discovery-resolved DCN version; `prepare` stays the 3.1.x path.
    pub fn prepare_dcn32<'a>(
        &'a self,
        vbios: &'a [u8],
    ) -> Result<firmware::Prepared<'a>, FirmwareError> {
        self.image()?
            .prepare_dcn32(vbios)
            .map_err(FirmwareError::Image)
    }
    /// Prepare a DCN 2.1 image (combined layout, as for 3.1.4 — see
    /// [`firmware::Image::prepare_dcn21`]). The returned `Prepared`
    /// records whether the firmware version takes the cached CW4
    /// mailbox or the uncached REGION4 one.
    pub fn prepare_dcn21<'a>(
        &'a self,
        vbios: &'a [u8],
    ) -> Result<firmware::Prepared<'a>, FirmwareError> {
        self.image()?
            .prepare_dcn21(vbios)
            .map_err(FirmwareError::Image)
    }
    /// Prepare a DCN 3.5 image (combined layout plus the Region6
    /// shared-state window — see [`firmware::Image::prepare_dcn35`]).
    /// Callers select by the discovery-resolved DCN version.
    pub fn prepare_dcn35<'a>(
        &'a self,
        vbios: &'a [u8],
    ) -> Result<firmware::Prepared<'a>, FirmwareError> {
        self.image()?
            .prepare_dcn35(vbios)
            .map_err(FirmwareError::Image)
    }
}

/// The DCN versions whose DMUB this module boots. Not a register window — the
/// gate is the firmware: DMUB's inbox ABI and its cache-window layout are
/// per-ASIC in Linux (`dmub_dcn314.c` against `dmub_dcn35.c`), and the blob
/// itself is named per version. Supporting another generation means another
/// blob and its own `dmub_dcn*` sequence, so this list stays in step with the
/// firmware this module actually knows how to hand over to.
///
/// DCN 3.1.5 (Raphael) is the same sequence: `dmub_srv.c` gives
/// `DMUB_ASIC_DCN315` every `dmub_dcn31_*` function DCN 3.1.4 uses, with only
/// the register table (`dmub_srv_dcn315_regs`) built from its own header, and
/// every DMCUB register both headers define sits at the same offset. DCN 3.1.5
/// lacks `DMCUB_EXT_INTERRUPT_STATUS` and `DMCUB_GPINT_DATAIN2..5`, which this
/// module does not use.
///
/// DCN 3.2.0 / 3.2.1 ride the same sequence for the same reason: every DMCUB
/// register `attach_regions` reads sits at the same offset in
/// `dcn_3_2_0_offset.h` / `dcn_3_2_1_offset.h` as in `dcn_3_1_4_offset.h`
/// (CNTL 0x1f6, CNTL2 0x200, SCRATCH0 0x1e3, SCRATCH7 0x1ea, INBOX1/OUTBOX1
/// 0x1d4–0x1df, CW4 base/top/offset 0x1a9/0x1b1/0x1bd/0x1be, FB_LOCATION
/// 0x475/0x476), and `dmub_dcn32_setup_windows` takes the same combined-image
/// layout as 3.1.4. The 3.2-specific reset and mailbox setup live in
/// `amdgpu_dmub_dcn32`, not here.
///
/// DCN 2.1 rides the same sequence for the same reason: `dmub_srv.c`
/// gives `DMUB_ASIC_DCN21` the DCN 2.0 functions (`dmub_srv_dcn20_regs`
/// and dcn20 funcs, with only the register table swapped to
/// `dmub_srv_dcn21_regs`), and every DMCUB register both tables define
/// sits at the same offset in `dcn_2_1_0_offset.h` as in
/// `dcn_2_0_0_offset.h`. The 2.1-specific reset and mailbox setup live
/// in `amdgpu_dmub_boot` (via `Regs::DCN21`), not here.
///
/// DCN 3.5.0 rides the same attach for the same reason: every register
/// `attach_regions` reads sits at the same offset in
/// `dcn_3_5_0_offset.h` as in `dcn_3_1_4_offset.h`. Two things do differ
/// and live outside this module: the Loader's hub-reset register is
/// `MMHUBBUB_SOFT_RESET` 0x341 on 3.5, not 0x342 (`amdgpu_dmub_boot`),
/// and `dmub_dcn35_setup_windows` programs a REGION6 shared-state
/// window (`prepare_dcn35` carries it; the Loader programs it only
/// when the image declares shared state). The 3.5-specific reset and
/// mailbox setup live in `amdgpu_dmub_dcn35`, not here.
const DMUB_VERSIONS: &[(u8, u8, u8)] = &[
    (2, 1, 0),
    (3, 1, 4),
    (3, 1, 5),
    (3, 2, 0),
    (3, 2, 1),
    (3, 5, 0),
];

pub(crate) fn dmub_ip(gpu: &AmdGpu) -> Result<&crate::amdgpu_discovery::IpBlock, Error> {
    let mut blocks = gpu
        .ip_blocks
        .iter()
        .filter(|b| b.hw_id == crate::amdgpu_discovery::HW_ID_DCN && b.instance == 0);
    let ip = blocks.next().ok_or(Error::Unsupported)?;
    if blocks.next().is_some() || !DMUB_VERSIONS.contains(&(ip.major, ip.minor, ip.revision)) {
        return Err(Error::Unsupported);
    }
    Ok(ip)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    NotReady,
    Invalid,
    Busy,
    Timeout,
    Firmware(u8),
    Aux(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Channel {
    Legacy = 0,
    Dpia = 1,
}
#[derive(Debug)]
pub struct Dmub {
    regs: MmioRegion,
    fb: MmioRegion,
    base: u64,
    inbox: u64,
    outbox: u64,
    inbox_size: u32,
    outbox_size: u32,
    write: u32,
    read: u32,
    poisoned: bool,
    dpias: u8,
    /// This generation's DMCUB register map, for the mailbox pointers.
    table: Regs,
}
/// The USB4 DPIAs this DCN's firmware serves: `dcn314_resource.c` sets
/// `usb4_dpia_count = 4`; `dcn315_resource.c` sets none, so Linux never sends
/// Raphael's firmware a DPIA command, and neither does this. Neither
/// `dcn32_resource.c` nor `dcn321_resource.c` sets one either, so DCN 3.2
/// serves none. Neither `dcn20_resource.c` nor `dcn21_resource.c` sets one
/// either, so DCN 2.1 serves none.
pub(crate) fn dpia_count(ip: &crate::amdgpu_discovery::IpBlock) -> u8 {
    match (ip.major, ip.minor, ip.revision) {
        (3, 1, 4) => 4,
        (3, 2, 0) | (3, 2, 1) => 0,
        // linux: n/a (no `dcn35_resource.c` in the ref tree to say
        // otherwise; fail-closed, no DPIA commands are sent).
        (3, 5, 0) => 0,
        _ => 0,
    }
}
impl Dmub {
    /// # Safety
    /// Caller exclusively owns the GPU's DMUB mailbox for the returned
    /// object's lifetime, including power management and firmware replacement.
    pub unsafe fn attach(gpu: &AmdGpu) -> Result<Self, Error> {
        let ip = dmub_ip(gpu)?;
        if ip.num_bases < 3 {
            return Err(Error::Unsupported);
        }
        let table =
            Regs::for_version((ip.major, ip.minor, ip.revision)).ok_or(Error::Unsupported)?;
        let base = ip.base_addrs[2] as u64 * 4;
        // Bound-check the bank before probing it: the probe below reads
        // a register inside it.
        if base
            .checked_add(table.bound as u64 * 4)
            .is_none_or(|end| end > gpu.regs.len)
        {
            return Err(Error::Invalid);
        }
        // The running firmware's mailbox mode: an uncached firmware
        // leaves INBOX1_BASE at the fixed 0x80000000, a cached one at
        // the CW4 window base. A stopped DMCUB reads 0 here and is
        // refused as NotReady below, so the cached default is safe.
        // SAFETY: bound-checked above; inherited mapping and exclusive
        // mailbox ownership.
        let cached_inbox =
            unsafe { gpu.regs.read32(base + u64::from(table.inbox1_base) * 4) } != 0x8000_0000;
        // SAFETY: inherited mapping and exclusive mailbox ownership.
        unsafe {
            Self::attach_regions(
                gpu.regs,
                gpu.fb_bar,
                base,
                dpia_count(ip),
                table,
                cached_inbox,
            )
        }
    }
    /// # Safety
    /// Valid DCN mappings and exclusive DMUB ownership must outlive Self.
    /// `table` is the register map for this GPU's DCN version, and
    /// `cached_inbox` is the mailbox mode the running firmware uses.
    pub(crate) unsafe fn attach_regions(
        regs: MmioRegion,
        fb: MmioRegion,
        base: u64,
        dpias: u8,
        table: Regs,
        cached_inbox: bool,
    ) -> Result<Self, Error> {
        if base
            .checked_add(table.bound as u64 * 4)
            .is_none_or(|end| end > regs.len)
        {
            return Err(Error::Invalid);
        }
        let mut d = Self {
            regs,
            fb,
            base,
            inbox: 0,
            outbox: 0,
            inbox_size: 0,
            outbox_size: 0,
            write: 0,
            read: 0,
            poisoned: false,
            dpias,
            table,
        };
        if d.reg(u64::from(table.cntl)) & (1 << 16) == 0 || d.reg(u64::from(table.status)) & 3 != 3
        {
            return Err(Error::NotReady);
        }
        // The mailbox window: the cached CW4 window, or the uncached
        // REGION4 window whose implied base is the fixed 0x80000000
        // (`dmub_dcn20_setup_windows`).
        let (window_base, window_end, address) = if cached_inbox {
            let window_base = d.reg(u64::from(table.cw_base + 4)) & 0x1fff_ffff;
            let top = d.reg(u64::from(table.cw_top + 4));
            if top & (1 << 31) == 0 {
                return Err(Error::NotReady);
            }
            let window_end = (top & 0x1fff_ffff) as u64;
            let address = d.reg(u64::from(table.cw_offset + 8)) as u64
                | ((d.reg(u64::from(table.cw_offset_high + 8)) as u64 & 0xffff) << 32);
            (window_base, window_end, address)
        } else {
            let region4_offset = table.region4_offset.ok_or(Error::Unsupported)?;
            let region4_offset_high = table.region4_offset_high.ok_or(Error::Unsupported)?;
            let region4_top = table.region4_top.ok_or(Error::Unsupported)?;
            let top = d.reg(u64::from(region4_top));
            if top & (1 << 31) == 0 {
                return Err(Error::NotReady);
            }
            let address = d.reg(u64::from(region4_offset)) as u64
                | ((d.reg(u64::from(region4_offset_high)) as u64 & 0xffff) << 32);
            // REGION4 has no BASE register; its implied base is 0x80000000.
            // TOP holds size - 1, so the window ends one past TOP.
            let window_end = 0x8000_0000u64 + (top & !0x8000_0000) as u64 + 1;
            (0x8000_0000, window_end, address)
        };
        // Read the aperture base from this IP's discovery window;
        // legacy MC offsets are not valid on every Phoenix revision.
        let fb_base = ((d.reg(u64::from(table.fb_base)) & 0x00ff_ffff) as u64) << 24;
        let fb_top = (((d.reg(u64::from(table.fb_top)) & 0x00ff_ffff) as u64) + 1) << 24;
        if fb_top <= fb_base || address >= fb_top {
            return Err(Error::Invalid);
        }
        let offset = address.checked_sub(fb_base).ok_or(Error::Invalid)?;
        // The cached path programs the rings' window bases in
        // INBOX1/OUTBOX1 (0x64000000 / 0x64002000); the uncached path
        // programs the raw 0x80000000 / 0x80002000 GPU addresses, which
        // must NOT be masked — the top bit is part of the address there.
        let (inbox_base, outbox_base) = if cached_inbox {
            (
                d.reg(u64::from(table.inbox1_base)) & 0x1fff_ffff,
                d.reg(u64::from(table.outbox1_base)) & 0x1fff_ffff,
            )
        } else {
            (
                d.reg(u64::from(table.inbox1_base)),
                d.reg(u64::from(table.outbox1_base)),
            )
        };
        d.inbox_size = d.reg(u64::from(table.inbox1_size));
        d.outbox_size = d.reg(u64::from(table.outbox1_size));
        d.inbox = mailbox_offset(
            offset,
            window_base,
            window_end,
            inbox_base,
            d.inbox_size,
            fb.len,
        )?;
        d.outbox = mailbox_offset(
            offset,
            window_base,
            window_end,
            outbox_base,
            d.outbox_size,
            fb.len,
        )?;
        if d.inbox < d.outbox + d.outbox_size as u64 && d.outbox < d.inbox + d.inbox_size as u64 {
            return Err(Error::Invalid);
        }
        d.write = d.reg(u64::from(table.inbox1_wptr));
        let read = d.reg(u64::from(table.inbox1_rptr));
        d.read = d.reg(u64::from(table.outbox1_rptr));
        let write = d.reg(u64::from(table.outbox1_wptr));
        if !valid_pointer(d.write, d.inbox_size)
            || !valid_pointer(read, d.inbox_size)
            || !valid_pointer(d.read, d.outbox_size)
            || !valid_pointer(write, d.outbox_size)
        {
            return Err(Error::Invalid);
        }
        if d.write != read {
            return Err(Error::Busy);
        }
        Ok(d)
    }
    fn reg(&self, offset: u64) -> u32 {
        // SAFETY: constructor validated the entire DCN mailbox register bank.
        unsafe { self.regs.read32(self.base + offset * 4) }
    }
    fn write_reg(&self, offset: u64, value: u32) {
        // SAFETY: constructor validated the register bank and caller owns DMUB.
        unsafe { self.regs.write32(self.base + offset * 4, value) };
    }
    fn read_slot(&self, offset: u64) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (i, word) in bytes.chunks_exact_mut(4).enumerate() {
            // SAFETY: constructor/pointer checks bound this whole ring entry.
            word.copy_from_slice(&unsafe { self.fb.read32(offset + i as u64 * 4) }.to_le_bytes());
        }
        bytes
    }
    fn outbox(&mut self) -> Result<Option<[u8; 64]>, Error> {
        let write = self.reg(u64::from(self.table.outbox1_wptr));
        if !valid_pointer(write, self.outbox_size) {
            self.poisoned = true;
            return Err(Error::Invalid);
        }
        if self.read == write {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        let command = self.read_slot(self.outbox + self.read as u64);
        self.read = (self.read + 64) % self.outbox_size;
        fence(Ordering::Release);
        self.write_reg(u64::from(self.table.outbox1_rptr), self.read);
        Ok(Some(command))
    }
    pub async fn command(&mut self, command: [u8; 64]) -> Result<[u8; 64], Error> {
        if self.poisoned {
            return Err(Error::NotReady);
        }
        if command[3] > 60 {
            return Err(Error::Invalid);
        }
        let next = (self.write + 64) % self.inbox_size;
        let read = self.reg(u64::from(self.table.inbox1_rptr));
        if !valid_pointer(read, self.inbox_size) {
            self.poisoned = true;
            return Err(Error::Invalid);
        }
        if next == read {
            return Err(Error::Busy);
        }
        let slot = self.inbox + self.write as u64;
        for (i, word) in command.chunks_exact(4).enumerate() {
            // SAFETY: driver owns the unposted slot; bounded mailbox mapping.
            unsafe {
                self.fb.write32(
                    slot + i as u64 * 4,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
        // Linux flushes the entire command from the WC framebuffer before
        // ringing WPTR. A CPU fence alone does not flush posted PCI writes.
        let _ = self.read_slot(slot);
        fence(Ordering::SeqCst);
        self.write = next;
        self.poisoned = true;
        self.write_reg(u64::from(self.table.inbox1_wptr), next);
        let deadline = narf_time::Deadline::after_ms(200);
        loop {
            let read = self.reg(u64::from(self.table.inbox1_rptr));
            if read == next {
                fence(Ordering::Acquire);
                let reply = self.read_slot(slot);
                if reply[0] != command[0] || reply[1] != command[1] || reply[3] != command[3] {
                    return Err(Error::Invalid);
                }
                self.poisoned = false;
                return Ok(reply);
            }
            if !valid_pointer(read, self.inbox_size) || deadline.expired() {
                self.poisoned = true;
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    pub async fn enable_notifications(&mut self) -> Result<(), Error> {
        // Discard boot firmware's pending replies before the first request.
        for _ in 0..self.outbox_size / 64 {
            if self.outbox()?.is_none() {
                break;
            }
        }
        let mut command = header(71, 0, 4);
        command[4] = 1;
        self.command(command).await.map(|_| ())
    }
    /// How many DPIAs the firmware serves (see [`dpia_count`]).
    pub(crate) fn dpias(&self) -> u8 {
        self.dpias
    }
    pub async fn hpd(&mut self, instance: u8, channel: Channel) -> Result<bool, Error> {
        let mut command = header(82, 0, 12);
        command[4] = instance;
        command[8..12].copy_from_slice(&(channel as u32).to_le_bytes());
        let reply = self.command(command).await?;
        if reply[12..16] != [0; 4] {
            return Err(Error::Firmware(reply[12]));
        }
        Ok(reply[5] != 0)
    }
    /// Returns (is USB-C PHY, DP Alt disabled, four DP lanes).
    pub async fn typec_phy(&mut self, phy: u8) -> Result<(bool, bool, bool), Error> {
        let mut command = header(128, 26, 4);
        command[4] = phy;
        let reply = self.command(command).await?;
        if reply[2] & 1 == 0 {
            return Err(Error::Firmware(0xff));
        }
        Ok((reply[5] != 0, reply[6] != 0, reply[7] != 0))
    }
    pub async fn aux(
        &mut self,
        channel: Channel,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        let command = aux_command(channel, instance, action, address, data)?;
        self.command(command).await?;
        self.poisoned = true;
        let deadline = narf_time::Deadline::after_ms(200);
        loop {
            for _ in 0..32 {
                let Some(reply) = self.outbox()? else {
                    break;
                };
                if reply[0] != 1 || reply[8] != instance {
                    continue;
                }
                let result = aux_reply(&reply, action, data);
                if result != Err(Error::Invalid) {
                    self.poisoned = false;
                }
                return result;
            }
            if deadline.expired() {
                // AUX replies have no usable request ID. Never submit another
                // AUX after timeout and risk assigning this late reply to it.
                self.poisoned = true;
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
}
fn valid_pointer(value: u32, size: u32) -> bool {
    value < size && value % 64 == 0
}
fn mailbox_offset(
    offset: u64,
    base: u32,
    end: u64,
    ring: u32,
    size: u32,
    aperture: u64,
) -> Result<u64, Error> {
    if !(128..=16384).contains(&size)
        || size % 64 != 0
        || ring < base
        || ring as u64 + size as u64 > end
    {
        return Err(Error::Invalid);
    }
    let start = offset
        .checked_add((ring - base) as u64)
        .ok_or(Error::Invalid)?;
    if start
        .checked_add(size as u64)
        .is_none_or(|end| end > aperture)
    {
        return Err(Error::Invalid);
    }
    Ok(start)
}
fn header(kind: u8, sub: u8, length: u8) -> [u8; 64] {
    let mut command = [0; 64];
    command[0] = kind;
    command[1] = sub;
    command[3] = length;
    command
}
pub(crate) fn aux_command(
    channel: Channel,
    instance: u8,
    action: u8,
    address: u32,
    data: &[u8],
) -> Result<[u8; 64], Error> {
    if (data.is_empty() && action >= 0x80)
        || data.len() > 16
        || address > 0xfffff
        || !matches!(action, 0 | 0x10 | 0x20 | 0x40 | 0x50 | 0x60 | 0x80 | 0x90)
    {
        return Err(Error::Invalid);
    }
    let mut command = header(70, 0, 36);
    command[4] = instance;
    command[8..10].copy_from_slice(&4000u16.to_le_bytes());
    command[12..16].copy_from_slice(&(channel as u32).to_le_bytes());
    command[16] = u8::from(action < 0x80);
    command[17] = action;
    command[18] = data.len() as u8;
    command[20..24].copy_from_slice(&address.to_le_bytes());
    if action & 0x10 == 0 {
        command[24..24 + data.len()].copy_from_slice(data);
    }
    Ok(command)
}
pub(crate) fn aux_reply(reply: &[u8; 64], action: u8, data: &mut [u8]) -> Result<(), Error> {
    if reply[3] < 28 || reply[3] > 60 {
        return Err(Error::Invalid);
    }
    if reply[9] != 0 {
        return Err(Error::Firmware(reply[9]));
    }
    let status = if reply[12] & 0xf0 != 0 {
        reply[12] >> 4
    } else {
        reply[12] & 15
    };
    if status != 0 {
        return Err(Error::Aux(status));
    }
    let length = reply[13] as usize;
    if length > 16 || (action & 0x10 != 0 && length != data.len()) {
        return Err(Error::Invalid);
    }
    if action & 0x10 == 0 && length != 0 && (length != 1 || reply[16] as usize != data.len()) {
        return Err(Error::Invalid);
    }
    if action & 0x10 != 0 {
        data.copy_from_slice(&reply[16..16 + length]);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    pub(crate) fn fixture_firmware() -> Firmware {
        Firmware {
            bytes: crate::amdgpu_dmub_firmware::tests::combined(256, 4),
        }
    }

    fn dmub_firmware_requires_exact_discovery_and_live_authority() -> TestResult {
        use crate::amdgpu::{ChipInfo, Family, AMD_VENDOR, PHOENIX_HAWKPOINT1};
        use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut gpu = AmdGpu {
            fb_bar: region,
            regs: region,
            chip: ChipInfo {
                vid: AMD_VENDOR,
                did: PHOENIX_HAWKPOINT1,
                family: Family::Phoenix,
                asic: "phoenix",
                fw_name: "amdgpu/unused.bin",
                fw_list: &[],
                revision: 0,
                rev_id: 0,
                mall_size: 0,
            },
            vram: Default::default(),
            mode: None,
            backlight_percent: None,
            fw_loaded: false,
            ip_blocks: alloc::vec![],
            vbios: None,
            // Synthetic fixture: no discovery blob, so no GC table.
            gc_info: None,
        };
        let (write, read) = narf_firmware::bootstrap_authority();
        write.revoke();
        if !matches!(Firmware::open(&gpu, &read), Err(FirmwareError::Unsupported)) {
            return TestResult::Fail("PCI family used as a substitute for DCN discovery");
        }
        let ip = IpBlock {
            hw_id: HW_ID_DCN,
            instance: 0,
            major: 3,
            minor: 1,
            revision: 4,
            sub_revision: 0,
            variant: 0,
            base_addrs: [0; MAX_BASE_ADDRS],
            num_bases: 3,
        };
        gpu.ip_blocks.push(ip);
        if !matches!(
            Firmware::open(&gpu, &read),
            Err(FirmwareError::Registry(
                narf_firmware::FirmwareError::AuthorityRevoked
            ))
        ) {
            return TestResult::Fail("firmware preparation ignored revoked registry authority");
        }
        gpu.ip_blocks.push(ip);
        if dmub_ip(&gpu).is_ok() {
            return TestResult::Fail("ambiguous DCN discovery accepted");
        }
        gpu.ip_blocks.pop();
        let firmware = Firmware {
            bytes: crate::amdgpu_dmub_firmware::tests::combined(256, 4),
        };
        if !matches!(
            firmware.prepare_from_gpu(&gpu),
            Err(FirmwareError::VbiosUnavailable)
        ) {
            return TestResult::Fail("missing platform VBIOS ignored");
        }
        gpu.vbios = Some(crate::amdgpu_vbios::tests::fixture());
        let prepared = match firmware.prepare_from_gpu(&gpu) {
            Ok(prepared) => prepared,
            Err(_) => return TestResult::Fail("validated platform VBIOS not usable by DMUB"),
        };
        let mut staged = alloc::vec![0; prepared.layout().size() as usize];
        let offset = prepared.layout().region(firmware::Window::Vbios).offset as usize;
        let bios = gpu.vbios.as_ref().unwrap().bytes();
        if prepared.stage(&mut staged).is_err() || &staged[offset..offset + bios.len()] != bios {
            return TestResult::Fail("platform VBIOS not copied to DMUB image");
        }
        // DCN 3.5.0 is admitted past the version gate (the revoked
        // authority is what refuses it here, not the version): the blob
        // name is `dcn_3_5_dmcub.bin`.
        gpu.ip_blocks[0].minor = 5;
        gpu.ip_blocks[0].revision = 0;
        if !matches!(
            Firmware::open(&gpu, &read),
            Err(FirmwareError::Registry(
                narf_firmware::FirmwareError::AuthorityRevoked
            ))
        ) {
            return TestResult::Fail("DCN 3.5 firmware path refused at the gate");
        }
        // Unlike 3.2, `prepare_dcn35` pins the image header to (3, 5),
        // so the fixture's minor version is patched from 1 to 5 first.
        let mut bytes35 = crate::amdgpu_dmub_firmware::tests::combined(256, 4);
        bytes35[14] = 5;
        let firmware35 = Firmware { bytes: bytes35 };
        let prepared = match firmware35.prepare_from_gpu(&gpu) {
            Ok(prepared) => prepared,
            Err(_) => return TestResult::Fail("DCN 3.5 image preparation refused"),
        };
        let mut staged = alloc::vec![0; prepared.layout().size() as usize];
        if prepared.stage(&mut staged).is_err() {
            return TestResult::Fail("DCN 3.5 image staging refused");
        }
        // DCN 3.2.0 / 3.2.1 are admitted past the version gate (the revoked
        // authority is what refuses them here, not the version): the blob
        // names are `dcn_3_2_0_dmcub.bin` / `dcn_3_2_1_dmcub.bin`.
        for revision in [0, 1] {
            gpu.ip_blocks[0].minor = 2;
            gpu.ip_blocks[0].revision = revision;
            if !matches!(
                Firmware::open(&gpu, &read),
                Err(FirmwareError::Registry(
                    narf_firmware::FirmwareError::AuthorityRevoked
                ))
            ) {
                return TestResult::Fail("DCN 3.2 firmware path refused at the gate");
            }
            let prepared = match firmware.prepare_from_gpu(&gpu) {
                Ok(prepared) => prepared,
                Err(_) => return TestResult::Fail("DCN 3.2 image preparation refused"),
            };
            let mut staged = alloc::vec![0; prepared.layout().size() as usize];
            if prepared.stage(&mut staged).is_err() {
                return TestResult::Fail("DCN 3.2 image staging refused");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        dmub_firmware_requires_exact_discovery_and_live_authority
    );

    fn dmub_mailbox_completion_wrap_and_cancel() -> TestResult {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let mut regs = alloc::vec![0u32; 0x201];
        let mut fb = alloc::vec![0u32; 64];
        let region = |ptr, len| MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: ptr,
            len,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let reg = region(regs.as_mut_ptr() as u64, regs.len() as u64 * 4);
        let vram = region(fb.as_mut_ptr() as u64, fb.len() as u64 * 4);
        let mut dmub = Dmub {
            regs: reg,
            fb: vram,
            base: 0,
            inbox: 0,
            outbox: 128,
            inbox_size: 128,
            outbox_size: 128,
            write: 0,
            read: 0,
            poisoned: false,
            dpias: 4,
            table: Regs::DCN314,
        };
        let mut cx = Context::from_waker(Waker::noop());
        for next in [64u32, 0, 64] {
            let slot = dmub.write as u64;
            let mut request = alloc::boxed::Box::pin(dmub.hpd(2, Channel::Dpia));
            if !matches!(request.as_mut().poll(&mut cx), Poll::Pending) {
                return TestResult::Fail("command completed before firmware consumed it");
            }
            // SAFETY: model-owned register/VRAM arrays outlive the transport.
            unsafe {
                if reg.read32(0x1d6 * 4) != next
                    || vram.read32(slot) != u32::from_le_bytes([82, 0, 0, 12])
                {
                    return TestResult::Fail("posted DMUB command/doorbell ABI");
                }
                vram.write32(slot + 4, 2 | (1 << 8));
                reg.write32(0x1d7 * 4, next);
            }
            if narf_scheduler::block_on_spin(request) != Ok(true) {
                return TestResult::Fail("completed HPD response or mailbox wrap");
            }
        }
        let mut request = alloc::boxed::Box::pin(dmub.hpd(2, Channel::Dpia));
        if !matches!(request.as_mut().poll(&mut cx), Poll::Pending) {
            return TestResult::Fail("pending cancellation setup");
        }
        drop(request);
        if narf_scheduler::block_on_spin(dmub.hpd(2, Channel::Dpia)) != Err(Error::NotReady) {
            return TestResult::Fail("cancelled request permitted stale-reply reuse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        dmub_mailbox_completion_wrap_and_cancel
    );
    fn dmub_aux_abi_and_reply_validation() -> TestResult {
        let c = aux_command(Channel::Dpia, 3, 0x90, 0x202, &[0; 6]).unwrap();
        if c[..4] != [70, 0, 0, 36]
            || c[4] != 3
            || c[12] != 1
            || c[17] != 0x90
            || c[18] != 6
            || c[20..24] != [2, 2, 0, 0]
        {
            return TestResult::Fail("DMUB AUX wire ABI");
        }
        let mut reply = header(1, 0, 28);
        reply[13] = 6;
        reply[16..22].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        let mut out = [0; 6];
        if aux_reply(&reply, 0x90, &mut out).is_err() || out != [1, 2, 3, 4, 5, 6] {
            return TestResult::Fail("AUX reply payload");
        }
        reply[13] = 17;
        if aux_reply(&reply, 0x90, &mut out).is_ok()
            || aux_command(Channel::Dpia, 0, 0x90, 0x100000, &[0]).is_ok()
        {
            return TestResult::Fail("AUX bounds");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu-dmub", dmub_aux_abi_and_reply_validation);
    fn dmub_mailbox_bounds() -> TestResult {
        if mailbox_offset(4096, 0x4000000, 0x4004000, 0x4002000, 8192, 65536) != Ok(12288)
            || mailbox_offset(0, 100, 1000, 0, 128, 4096).is_ok()
            || mailbox_offset(u64::MAX, 0, 16384, 0, 8192, u64::MAX).is_ok()
            || valid_pointer(8192, 8192)
            || valid_pointer(3, 8192)
        {
            return TestResult::Fail("untrusted ring range/pointer accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu-dmub", dmub_mailbox_bounds);

    /// DCN 3.1.4 serves four DPIAs (`dcn314_resource.c`); DCN 3.1.5 serves none
    /// (`dcn315_resource.c` sets no `usb4_dpia_count`), so the sink scan sends
    /// Raphael's firmware no DPIA command. DCN 3.2.0 / 3.2.1 serve none
    /// either (`dcn32_resource.c` / `dcn321_resource.c` set none).
    fn dmub_dpia_count_follows_the_dcn() -> TestResult {
        use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};
        let ip = |minor, revision| IpBlock {
            hw_id: HW_ID_DCN,
            instance: 0,
            major: 3,
            minor,
            revision,
            sub_revision: 0,
            variant: 0,
            base_addrs: [0; MAX_BASE_ADDRS],
            num_bases: 3,
        };
        if dpia_count(&ip(1, 4)) != 4 || dpia_count(&ip(1, 5)) != 0 {
            return TestResult::Fail("DPIA count per DCN");
        }
        if dpia_count(&ip(2, 0)) != 0 || dpia_count(&ip(2, 1)) != 0 {
            return TestResult::Fail("DCN 3.2 must serve no DPIA");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu-dmub", dmub_dpia_count_follows_the_dcn);
}
