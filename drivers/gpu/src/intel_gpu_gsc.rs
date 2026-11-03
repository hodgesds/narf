//! MTL/Arrow media-GT GSC firmware, GSC-headered HuC images and the GSC
//! HECI packet protocol, as data formats only.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! - xe_uc_fw.c `XE_GSC_FIRMWARE_DEFS` / `XE_HUC_FIRMWARE_DEFS` (METEORLAKE,
//!   GT_TYPE_ANY): `i915/mtl_gsc_1.bin` matched on its compatibility version
//!   102.1.0 (major only), `i915/mtl_huc_gsc.bin` with no version requirement.
//!   Separate `gsc_firmware_path` / `huc_firmware_path` module parameters
//!   (an empty string disables each) make GSC and HuC independently optional.
//! - xe_uc_fw.c::{parse_gsc_layout,parse_cpd_header,entry_offset,
//!   parse_css_header,parse_headers,xe_uc_fw_check_version_requirements} and
//!   xe_uc_fw_abi.h (layout pointers, BPDT, CPD, manifest and CSS headers).
//! - xe_gsc_submit.c::{xe_gsc_emit_header,xe_gsc_check_and_update_pending,
//!   xe_gsc_read_out_header,xe_gsc_pkt_submit_kernel},
//!   abi/gsc_command_header_abi.h and instructions/xe_gsc_commands.h.
//! - xe_gsc.c::{emit_gsc_upload,query_compatibility_version,gsc_fw_wait} and
//!   abi/gsc_mkhi_commands_abi.h.
//! - xe_huc.c::{huc_emit_pxp_auth_msg,huc_auth_via_gsccs,huc_auth_modes} and
//!   abi/gsc_pxp_commands_abi.h.
//!
//! In Linux the MTL HuC is DMA-loaded from the CSS inside its GSC image and
//! first authenticated by the media GuC (xe_uc_load_hw: xe_huc_upload, then
//! xe_huc_auth(XE_HUC_AUTH_VIA_GUC)); that alone sets it RUNNING, which is
//! what query_uc_fw_version reports. GSC authentication is a second step run
//! from gsc_upload_and_init after the GSC firmware loaded, and it precedes
//! xe_gsc_proxy_start: huc_auth_via_gsccs only needs a GSCCS HECI packet to
//! HECI_MEADDRESS_PXP, never the MEI proxy component.
//!
//! No owner loads GSC firmware, brings up GSCCS or loads the MTL HuC yet; the
//! media GT path keeps refusing to schedule while GSC firmware is loaded.

#![cfg_attr(not(feature = "kernel-test"), allow(dead_code))]

use crate::intel_gpu_aux::MmioWindow;

/// xe_uc_fw.c fw_filename_gsc(i915, gsc, mtl, 102, 1, 0): the name carries
/// the compatibility minor.
pub(crate) const GSC_FIRMWARE: &str = "i915/mtl_gsc_1.bin";
/// The wanted GSC compatibility version (versions.wanted_type is
/// XE_UC_FW_VER_COMPATIBILITY for GSC; major_ver: full version not required).
pub(crate) const GSC_WANTED: Version = Version::new(102, 1, 0, 0);
/// xe_uc_fw.c no_ver(i915, huc_gsc, mtl): any HuC release is accepted.
pub(crate) const HUC_FIRMWARE: &str = "i915/mtl_huc_gsc.bin";
/// xe_gsc.c::xe_gsc_init_post_hwconfig: the GSC private (stolen) object.
pub(crate) const PRIVATE_BYTES: usize = 4 << 20;
/// xe_gsc.c::gsc_fw_wait: HECI1_FWSTS1 INIT_COMPLETE within 500 ms.
pub(crate) const LOAD_WAIT_NS: u64 = 500_000_000;
/// xe_gsc.c GSC_VER_PKT_SZ and xe_huc.c PXP43_HUC_AUTH_INOUT_SIZE: 4 KiB for
/// the input and 4 KiB for the output half of one packet object.
pub(crate) const PACKET_HALF: u32 = 4096;
/// xe_huc.c::huc_auth_via_gsccs: five submissions while the GSC reports a
/// pending message, 50 ms apart.
pub(crate) const AUTH_ATTEMPTS: u32 = 5;
pub(crate) const AUTH_RETRY_NS: u64 = 50_000_000;
/// xe_huc.c::xe_huc_auth: the authentication bit must appear within 100 ms.
pub(crate) const AUTH_WAIT_NS: u64 = 100_000_000;

/// Errors carry the Linux errno each source branch returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GscError {
    /// -ENOENT: no CPD marker (a HuC image then falls back to CSS).
    NotCpd,
    /// -EINVAL: malformed CPD header length or BPDT signature, or a reply
    /// header reporting a nonzero status.
    Invalid,
    /// -ENODATA: a structure, entry or payload does not fit or is missing.
    NoData,
    /// -EPROTO: CSS header-size integrity, or a reply without the marker.
    Protocol,
    /// -ENOEXEC: CSS sizes exceed the blob, or a GSC compatibility major
    /// other than the wanted one.
    NoExec,
    /// -ENOMEM: the output buffer cannot hold a GSC header.
    NoMemory,
    /// -EIO: the GSC rejected HuC authentication.
    Io,
    /// The GSC image does not fit its 4 MiB private object (Linux copies it
    /// there unchecked).
    TooLarge,
}

/// xe_uc_fw_version / gsc_version: major, minor, patch (hotfix), build.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl Version {
    pub(crate) const fn new(major: u16, minor: u16, patch: u16, build: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

/// struct uc_css_header is 128 bytes.
pub(crate) const CSS_HEADER: usize = 128;
const LAYOUT_POINTERS: usize = 80;
const BPDT_HEADER: usize = 24;
const BPDT_ENTRY: usize = 12;
const BPDT_SIGNATURE: u32 = 0x0000_55aa;
const BPDT_TYPE_GSC_RBE: u32 = 0x1;
const CPD_HEADER: usize = 20;
const CPD_ENTRY: usize = 24;
const CPD_MARKER: u32 = 0x4450_4324;
const CPD_OFFSET_MASK: u32 = (1 << 25) - 1;
const MANIFEST_HEADER: usize = 128;

/// xe_uc_fw.c::parse_css_header over `data`. The dword differences keep the
/// source's wrapping u32 arithmetic, but the byte sizes are not truncated
/// into u32 fields as uc_fw->ucode_size/rsa_size are: an extent that fits
/// the blob only after truncation is refused as ENOEXEC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Css {
    pub(crate) release: Version,
    pub(crate) ucode_size: usize,
    pub(crate) rsa_size: usize,
}

pub(crate) fn parse_css(data: &[u8]) -> Result<Css, GscError> {
    if data.len() < CSS_HEADER {
        return Err(GscError::NoData);
    }
    let header = u32_at(data, 4);
    let (key, modulus, exponent) = (u32_at(data, 28), u32_at(data, 32), u32_at(data, 36));
    let size = u64::from(
        header
            .wrapping_sub(key)
            .wrapping_sub(modulus)
            .wrapping_sub(exponent),
    ) * 4;
    if size != CSS_HEADER as u64 {
        return Err(GscError::Protocol);
    }
    let ucode = u64::from(u32_at(data, 24).wrapping_sub(header)) * 4;
    let rsa = u64::from(key) * 4;
    if (data.len() as u64) < CSS_HEADER as u64 + ucode + rsa {
        return Err(GscError::NoExec);
    }
    let version = u32_at(data, 64);
    Ok(Css {
        release: Version::new(
            (version >> 16 & 0xff) as u16,
            (version >> 8 & 0xff) as u16,
            (version & 0xff) as u16,
            0,
        ),
        ucode_size: ucode as usize,
        rsa_size: rsa as usize,
    })
}

/// xe_uc_fw.c::entry_offset: the masked offset of the entry whose
/// NUL-terminated name is `name` (strcmp over the 12-byte field), or 0.
fn entry_offset(cpd: &[u8], name: &str) -> u32 {
    let first = usize::from(cpd[10]);
    let count = u32_at(cpd, 4) as usize;
    let name = name.as_bytes();
    (0..count)
        .map(|index| &cpd[first + index * CPD_ENTRY..first + (index + 1) * CPD_ENTRY])
        .find(|entry| entry[..name.len()] == *name && entry[name.len()] == 0)
        .map_or(0, |entry| u32_at(entry, 12) & CPD_OFFSET_MASK)
}

/// What xe_uc_fw.c::parse_cpd_header establishes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cpd {
    /// Manifest fw_version (major, minor, hotfix, build).
    pub(crate) manifest: Version,
    pub(crate) security_version: u32,
    /// The CSS entry's offset and header, when one was requested.
    pub(crate) css: Option<(usize, Css)>,
}

pub(crate) fn parse_cpd(
    data: &[u8],
    manifest_entry: &str,
    css_entry: Option<&str>,
) -> Result<Cpd, GscError> {
    if data.len() < CPD_HEADER || u32_at(data, 0) != CPD_MARKER {
        return Err(GscError::NotCpd);
    }
    let header_length = usize::from(data[10]);
    if header_length < CPD_HEADER {
        return Err(GscError::Invalid);
    }
    let entries = (u32_at(data, 4) as usize)
        .checked_mul(CPD_ENTRY)
        .and_then(|bytes| bytes.checked_add(header_length))
        .ok_or(GscError::NoData)?;
    if data.len() < entries {
        return Err(GscError::NoData);
    }
    let offset = entry_offset(data, manifest_entry) as usize;
    if offset == 0 {
        return Err(GscError::NoData);
    }
    if data.len() < offset + MANIFEST_HEADER {
        return Err(GscError::NoData);
    }
    let manifest = &data[offset..offset + MANIFEST_HEADER];
    let mut cpd = Cpd {
        manifest: Version::new(
            u16_at(manifest, 36),
            u16_at(manifest, 38),
            u16_at(manifest, 40),
            u16_at(manifest, 42),
        ),
        security_version: u32_at(manifest, 44),
        css: None,
    };
    if let Some(name) = css_entry {
        // A missing CSS entry is offset 0, as in the source: the CPD header
        // itself is then parsed as CSS and refused by its integrity check.
        let offset = entry_offset(data, name) as usize;
        if offset > data.len() {
            return Err(GscError::NoData);
        }
        cpd.css = Some((offset, parse_css(&data[offset..])?));
    }
    Ok(cpd)
}

/// The MTL GSC firmware as xe_uc_fw.c::parse_gsc_layout reads it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct GscImage {
    /// RBEP.man fw_version, including the build (release, not compatibility).
    pub(crate) release: Version,
    pub(crate) security_version: u32,
    /// Bytes memcpy_fw copies into the private object.
    pub(crate) size: usize,
}

impl GscImage {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, GscError> {
        if data.len() < LAYOUT_POINTERS {
            return Err(GscError::NoData);
        }
        let (offset, size) = (u32_at(data, 32) as usize, u32_at(data, 36) as usize);
        // The source adds two u32s; a wrapping extent refuses here.
        let end = offset.checked_add(size).ok_or(GscError::NoData)?;
        if data.len() < end {
            return Err(GscError::NoData);
        }
        if size < BPDT_HEADER {
            return Err(GscError::NoData);
        }
        let boot1 = &data[offset..end];
        if u32_at(boot1, 0) != BPDT_SIGNATURE {
            return Err(GscError::Invalid);
        }
        let count = usize::from(u16_at(boot1, 4));
        if size < BPDT_HEADER + BPDT_ENTRY * count {
            return Err(GscError::NoData);
        }
        for index in 0..count {
            let entry = &boot1[BPDT_HEADER + index * BPDT_ENTRY..][..BPDT_ENTRY];
            if u32_at(entry, 0) & 0xffff != BPDT_TYPE_GSC_RBE {
                continue;
            }
            let partition = u32_at(entry, 4) as usize;
            if size < partition {
                return Err(GscError::NoData);
            }
            let cpd = parse_cpd(&boot1[partition..], "RBEP.man", None)?;
            if data.len() > PRIVATE_BYTES {
                return Err(GscError::TooLarge);
            }
            return Ok(Self {
                release: cpd.manifest,
                security_version: cpd.security_version,
                size: data.len(),
            });
        }
        Err(GscError::NoData)
    }
}

/// xe_uc_fw_check_version_requirements for the GSC compatibility version
/// reported after load: only the major must match (major_ver entry); an
/// older minor/patch is a notice, not a refusal.
pub(crate) fn check_compatibility(found: Version) -> Result<(), GscError> {
    if found.major != GSC_WANTED.major {
        return Err(GscError::NoExec);
    }
    Ok(())
}

/// The MTL HuC image as xe_uc_fw.c::parse_headers reads a HuC: GSC CPD
/// headers (HUCP.man, huc_fw) or, without a CPD marker, a whole-file CSS.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct HucImage {
    /// versions.found[RELEASE]: parse_css_header overwrites the manifest
    /// version with the CSS sw_version, so this is what Xe reports.
    pub(crate) release: Version,
    /// uc_fw->css_offset: the DMA source within the image.
    pub(crate) css_offset: usize,
    pub(crate) ucode_size: usize,
    pub(crate) rsa_size: usize,
    /// uc_fw->has_gsc_headers: only then may the GSC authenticate it.
    pub(crate) gsc_headers: bool,
    pub(crate) size: usize,
}

impl HucImage {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, GscError> {
        let (css_offset, css, gsc_headers) = match parse_cpd(data, "HUCP.man", Some("huc_fw")) {
            Ok(cpd) => {
                let (offset, css) = cpd.css.expect("requested CSS entry");
                (offset, css, true)
            }
            Err(GscError::NotCpd) => (0, parse_css(data)?, false),
            Err(error) => return Err(error),
        };
        Ok(Self {
            release: css.release,
            css_offset,
            ucode_size: css.ucode_size,
            rsa_size: css.rsa_size,
            gsc_headers,
            size: data.len(),
        })
    }

    /// uc_fw_xfer: DMA_COPY_SIZE is the CSS header plus uCode.
    pub(crate) fn dma_bytes(&self) -> usize {
        CSS_HEADER + self.ucode_size
    }

    /// xe_uc_fw_rsa_offset: what XE_HUC_AUTH_VIA_GUC passes (plus the GGTT
    /// base of the whole image).
    pub(crate) fn rsa_offset(&self) -> usize {
        self.css_offset + CSS_HEADER + self.ucode_size
    }
}

/// struct intel_gsc_mtl_header (packed, 36 bytes).
pub(crate) const HEADER: usize = 36;
const VALIDITY_MARKER: u32 = 0xa578_875a;
const HEADER_VERSION: u16 = 1;
const OUTFLAG_PENDING: u32 = 1 << 0;
const HOST_SESSION_CLIENT_SHIFT: u32 = 56;
/// abi/gsc_mkhi_commands_abi.h / abi/gsc_pxp_commands_abi.h HECI clients.
pub(crate) const HECI_MKHI: u8 = 7;
pub(crate) const HECI_PXP: u8 = 17;

/// xe_gsc_submit.c::xe_gsc_emit_header into `out` (zeroed first); returns
/// the payload offset. A host session may not use the client byte.
pub(crate) fn emit_header(
    out: &mut [u8],
    client: u8,
    session: u64,
    payload: u32,
) -> Result<usize, GscError> {
    if out.len() < HEADER || session >> HOST_SESSION_CLIENT_SHIFT != 0 {
        return Err(GscError::Invalid);
    }
    let session = if session != 0 {
        session | u64::from(client) << HOST_SESSION_CLIENT_SHIFT
    } else {
        0
    };
    out[..HEADER].fill(0);
    out[..4].copy_from_slice(&VALIDITY_MARKER.to_le_bytes());
    out[4] = client;
    out[6..8].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    out[8..16].copy_from_slice(&session.to_le_bytes());
    let size = payload
        .checked_add(HEADER as u32)
        .ok_or(GscError::Invalid)?;
    out[24..28].copy_from_slice(&size.to_le_bytes());
    Ok(HEADER)
}

/// xe_gsc_submit.c::xe_gsc_read_out_header: the payload offset of a valid,
/// successful reply carrying at least `min_payload` bytes.
pub(crate) fn read_out_header(reply: &[u8], min_payload: u32) -> Result<usize, GscError> {
    if reply.len() < HEADER {
        return Err(GscError::NoData);
    }
    let size = u32_at(reply, 24);
    if u32_at(reply, 0) != VALIDITY_MARKER {
        return Err(GscError::Protocol);
    }
    if u32_at(reply, 32) != 0 {
        return Err(GscError::Invalid);
    }
    if size < HEADER as u32 || size - (HEADER as u32) < min_payload {
        return Err(GscError::NoData);
    }
    Ok(HEADER)
}

/// xe_gsc_submit.c::xe_gsc_check_and_update_pending: a pending reply hands
/// its gsc_message_handle back to the next submission of `input`.
pub(crate) fn check_and_update_pending(input: &mut [u8], reply: &[u8]) -> bool {
    if u32_at(reply, 28) & OUTFLAG_PENDING == 0 {
        return false;
    }
    let handle = u64_at(reply, 16);
    input[16..24].copy_from_slice(&handle.to_le_bytes());
    true
}

/// instructions/xe_gsc_commands.h: XE_INSTR_GSC with opcode/length fields.
pub(crate) const GSC_HECI_CMD_PKT: u32 = 2 << 29 | 6;
pub(crate) const GSC_FW_LOAD: u32 = 2 << 29 | 1 << 22 | 2;
const GSC_FW_LOAD_LIMIT_VALID: u32 = 1 << 31;

/// xe_gsc_submit.c::xe_gsc_pkt_submit_kernel's eight-dword batch.
pub(crate) fn heci_packet(
    input: u64,
    input_size: u32,
    output: u64,
    output_size: u32,
) -> Result<[u32; 8], GscError> {
    if input_size < HEADER as u32 {
        return Err(GscError::NoData);
    }
    if output_size < HEADER as u32 {
        return Err(GscError::NoMemory);
    }
    Ok([
        GSC_HECI_CMD_PKT,
        input as u32,
        (input >> 32) as u32,
        input_size,
        output as u32,
        (output >> 32) as u32,
        output_size,
        0,
    ])
}

/// xe_gsc.c::emit_gsc_upload: GSC_FW_LOAD of the private object, its size in
/// 4 KiB pages with GSC_FW_LOAD_LIMIT_VALID.
pub(crate) fn fw_load(private: u64, private_bytes: usize) -> [u32; 4] {
    [
        GSC_FW_LOAD,
        private as u32,
        (private >> 32) as u32,
        (private_bytes / 4096) as u32 | GSC_FW_LOAD_LIMIT_VALID,
    ]
}

/// MKHI_GROUP_ID_GFX_SRV / MKHI_GFX_SRV_GET_HOST_COMPATIBILITY_VERSION.
const MKHI_GFX_SRV: u8 = 0x30;
const MKHI_GET_COMPATIBILITY: u8 = 0x42;
const COMPATIBILITY_IN: u32 = 4;
const COMPATIBILITY_OUT: u32 = 20;

/// xe_gsc.c::query_compatibility_version input: header plus
/// gsc_get_compatibility_version_in. Returns the input size.
pub(crate) fn compatibility_query(out: &mut [u8]) -> Result<u32, GscError> {
    let at = emit_header(out, HECI_MKHI, 0, COMPATIBILITY_IN)?;
    let end = at + COMPATIBILITY_IN as usize;
    if out.len() < end {
        return Err(GscError::Invalid);
    }
    out[at..end].copy_from_slice(&[MKHI_GFX_SRV, MKHI_GET_COMPATIBILITY, 0, 0]);
    Ok(end as u32)
}

/// The reply: compatibility major = proj_major, minor = compat_major,
/// patch = compat_minor (the source does not inspect the MKHI result).
pub(crate) fn compatibility_reply(reply: &[u8]) -> Result<Version, GscError> {
    let at = read_out_header(reply, COMPATIBILITY_OUT)?;
    if reply.len() < at + COMPATIBILITY_OUT as usize {
        return Err(GscError::NoData);
    }
    Ok(Version::new(
        u16_at(reply, at + 4),
        u16_at(reply, at + 6),
        u16_at(reply, at + 8),
        0,
    ))
}

/// PXP_APIVER(4, 3), PXP43_CMDID_NEW_HUC_AUTH and the pxp_status values
/// huc_auth_via_gsccs accepts.
const PXP_API_4_3: u32 = 4 << 16 | 3;
const PXP43_NEW_HUC_AUTH: u32 = 0x3f;
const PXP_CMD_HEADER: u32 = 16;
const HUC_AUTH_IN: u32 = 28;
const PXP_STATUS_SUCCESS: u32 = 0;
const PXP_STATUS_OP_NOT_PERMITTED: u32 = 0x4013;

/// xe_huc.c::huc_emit_pxp_auth_msg behind a PXP header: the whole HuC
/// object's GGTT address and xe_bo_size (the object, not the file, size).
/// Returns the input size.
pub(crate) fn huc_auth_request(out: &mut [u8], huc: u64, huc_size: u32) -> Result<u32, GscError> {
    let at = emit_header(out, HECI_PXP, 0, HUC_AUTH_IN)?;
    let end = at + HUC_AUTH_IN as usize;
    if out.len() < end {
        return Err(GscError::Invalid);
    }
    let message = &mut out[at..end];
    message.fill(0);
    message[..4].copy_from_slice(&PXP_API_4_3.to_le_bytes());
    message[4..8].copy_from_slice(&PXP43_NEW_HUC_AUTH.to_le_bytes());
    message[12..16].copy_from_slice(&(HUC_AUTH_IN - PXP_CMD_HEADER).to_le_bytes());
    message[16..24].copy_from_slice(&huc.to_le_bytes());
    message[24..28].copy_from_slice(&huc_size.to_le_bytes());
    Ok(end as u32)
}

/// The reply of a non-pending HuC authentication packet. OP_NOT_PERMITTED
/// means already authenticated; the auth bit is checked afterwards anyway.
pub(crate) fn huc_auth_reply(reply: &[u8]) -> Result<(), GscError> {
    let at = read_out_header(reply, PXP_CMD_HEADER)?;
    if reply.len() < at + PXP_CMD_HEADER as usize {
        return Err(GscError::NoData);
    }
    match u32_at(reply, at + 8) {
        PXP_STATUS_SUCCESS | PXP_STATUS_OP_NOT_PERMITTED => Ok(()),
        _ => Err(GscError::Io),
    }
}

/// xe_huc.c `huc_auth_modes`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HucAuth {
    /// HUC_KERNEL_LOAD_INFO & HUC_LOAD_SUCCESSFUL (GSI-adjusted on GT1).
    Guc,
    /// HECI_FWSTS5(MTL_GSC_HECI1_BASE) & HECI1_FWSTS5_HUC_AUTH_DONE
    /// (absolute).
    Gsc,
}

const HUC_KERNEL_LOAD_INFO: u64 = 0xc1dc;
const HUC_LOAD_SUCCESSFUL: u32 = 1 << 0;
const HECI1_FWSTS5: u64 = 0x116000 + 0xc68;
const HECI1_FWSTS5_HUC_AUTH_DONE: u32 = 1 << 19;

/// xe_huc.c::xe_huc_is_authenticated through the media GT's MMIO view
/// (`MediaGsi`); an all-ones read is lost MMIO, never authentication.
pub(crate) fn huc_authenticated(media: &impl MmioWindow, mode: HucAuth) -> Option<bool> {
    let (reg, bit) = match mode {
        HucAuth::Guc => (HUC_KERNEL_LOAD_INFO, HUC_LOAD_SUCCESSFUL),
        HucAuth::Gsc => (HECI1_FWSTS5, HECI1_FWSTS5_HUC_AUTH_DONE),
    };
    let value = media.read32(reg);
    (value != u32::MAX).then_some(value & bit != 0)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_gsc_tests.rs"]
mod tests;
