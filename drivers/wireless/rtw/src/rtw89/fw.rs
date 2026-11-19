//! AX firmware preparation contracts. The parser and owned file selector live
//! in `fwdl` and `prepared`; `firmware_registry` obtains verified snapshots.
//! Preparation does not establish power, secure-fuse, DMA or WCPU readiness.
use super::mac::ChipId;

/// Unversioned canonical fallback. The owned loader tries Linux's supported
/// versioned names first; a missing file permits an older filename.
pub const fn expected_blob_name(chip_id: ChipId) -> Option<&'static str> {
    match chip_id {
        ChipId::Rtl8852A => Some("rtw89/rtw8852a_fw.bin"),
        ChipId::Rtl8852B => Some("rtw89/rtw8852b_fw.bin"),
        ChipId::Rtl8852C => Some("rtw89/rtw8852c_fw.bin"),
        ChipId::Rtl8851B => Some("rtw89/rtw8851b_fw.bin"),
        ChipId::Rtl8922A => Some("rtw89/rtw8922a_fw.bin"),
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// No registered file under any supported canonical name.
    BlobMissing,
    /// No applicable non-manufacturing image for this physical cut/type.
    ImageMissing,
    /// Trusted firmware capability is unavailable or revoked.
    Authority,
    /// Owned preparation could not reserve storage.
    NoMemory,
    /// Invalid header, TOC, signature-pool or payload extent.
    BadFormat,
    /// Unimplemented container, layout or secure-loader selection policy.
    UnsupportedFormat,
    DmaTimeout,
    WcpuTimeout,
}
