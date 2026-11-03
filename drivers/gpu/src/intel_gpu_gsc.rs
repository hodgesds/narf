//! MTL/Arrow media-GT GSC firmware, GSC-headered HuC images and the GSC
//! HECI packet protocol.
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
//! The HuC parts below are production: `intel_gpu_huc` acquires
//! `HUC_FIRMWARE`, stages its `HucImage` CSS window on the media GuC and reads
//! `huc_authenticated(_, HucAuth::Guc)` through GT1's view. The GSC-only parts
//! (`heci`: the GSC image, its load batch and the HECI protocol, including GSC
//! HuC authentication) stay formats: no owner loads GSC firmware or brings up
//! GSCCS, and the media GT path keeps refusing to schedule while GSC firmware
//! is loaded.

use crate::intel_gpu_aux::MmioWindow;

#[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
#[path = "intel_gpu_gsc_heci.rs"]
mod heci;
#[cfg_attr(not(feature = "kernel-test"), allow(unused_imports))]
pub(crate) use heci::*;

/// xe_uc_fw.c no_ver(i915, huc_gsc, mtl): any HuC release is accepted.
pub(crate) const HUC_FIRMWARE: &str = "i915/mtl_huc_gsc.bin";
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
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    NoMemory,
    /// -EIO: the GSC rejected HuC authentication.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    Io,
    /// The GSC image does not fit its 4 MiB private object (Linux copies it
    /// there unchecked).
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    TooLarge,
}

/// xe_uc_fw_version / gsc_version: major, minor, patch (hotfix), build.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    /// Read only by the GSC release (manifest) path.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
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

/// struct uc_css_header is 128 bytes.
pub(crate) const CSS_HEADER: usize = 128;
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
    /// Manifest fw_version (major, minor, hotfix, build). The HuC release
    /// is the CSS's instead; only the GSC image reports this one.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) manifest: Version,
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
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
    /// parse_css_header bounds it by the blob; nothing else reads it.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) rsa_size: usize,
    /// uc_fw->has_gsc_headers: only then may the GSC authenticate it.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) gsc_headers: bool,
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
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

/// xe_huc.c `huc_auth_modes`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HucAuth {
    /// HUC_KERNEL_LOAD_INFO & HUC_LOAD_SUCCESSFUL (GSI-adjusted on GT1).
    Guc,
    /// HECI_FWSTS5(MTL_GSC_HECI1_BASE) & HECI1_FWSTS5_HUC_AUTH_DONE
    /// (absolute). Unused until NARF authenticates HuC via the GSC.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    Gsc,
}

const HUC_KERNEL_LOAD_INFO: u64 = 0xc1dc;
const HUC_LOAD_SUCCESSFUL: u32 = 1 << 0;
const HECI1_FWSTS5: u64 = 0x116000 + 0xc68;
const HECI1_FWSTS5_HUC_AUTH_DONE: u32 = 1 << 19;

/// xe_huc.c::xe_huc_is_authenticated through the HuC-owning GT's MMIO view:
/// the media GT's `MediaGsi` on MTL/Arrow, GT0's window on exact TGL. An
/// all-ones read is lost MMIO, never authentication.
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
