//! GSC-only formats of the MTL/Arrow media GT: the GSC firmware image and its
//! GSC_FW_LOAD batch, and the GSC HECI packet protocol (MKHI compatibility
//! query, PXP 4.3 HuC authentication). Sources are listed in the parent
//! module. Nothing uses these until NARF loads GSC firmware, so the parent
//! mounts this module with a dead-code allowance outside native tests.

use super::{parse_cpd, u16_at, u32_at, GscError, Version};

/// xe_uc_fw.c fw_filename_gsc(i915, gsc, mtl, 102, 1, 0): the name carries
/// the compatibility minor.
pub(crate) const GSC_FIRMWARE: &str = "i915/mtl_gsc_1.bin";
/// The wanted GSC compatibility version (versions.wanted_type is
/// XE_UC_FW_VER_COMPATIBILITY for GSC; major_ver: full version not required).
pub(crate) const GSC_WANTED: Version = Version::new(102, 1, 0, 0);
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

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

const LAYOUT_POINTERS: usize = 80;
const BPDT_HEADER: usize = 24;
const BPDT_ENTRY: usize = 12;
const BPDT_SIGNATURE: u32 = 0x0000_55aa;
const BPDT_TYPE_GSC_RBE: u32 = 0x1;

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
