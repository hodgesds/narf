//! `firmware-N.bin` — the IE container Linux prefers over the separate
//! `amss.bin` / `m3.bin` files.
//!
//! A port of `drivers/net/wireless/ath/ath11k/fw.{c,h}`:
//!
//! - [`parse_api_n`] = `ath11k_fw_request_firmware_api_n`'s parse: the
//!   NUL-terminated magic `"QCOM-ATH11K-FW"`, padded to 4 bytes, then
//!   `struct ath11k_fw_ie { __le32 id; __le32 len; u8 data[]; }` elements,
//!   each padded to 4 bytes. TIMESTAMP (only when 4 bytes), FEATURES
//!   (bits `0..ATH11K_FW_FEATURE_COUNT`), AMSS_IMAGE and M3_IMAGE are
//!   recorded; any other id is reported and skipped.
//! - [`FwApi::pre_init`] = `ath11k_fw_pre_init`: `firmware-2.bin` when it
//!   loads and parses (`api_version = 2`), else `api_version = 1`.
//!   Neither case fails the probe.
//!
//! The users pick the images the way Linux does: `ath11k_mhi_register`
//! boots the AMSS IE when it is non-empty, else `amss.bin`
//! ([`FwApi::amss`]); `ath11k_qmi_m3_load` uses the M3 IE when it is
//! non-empty, else `m3.bin` ([`FwApi::m3`]).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::ops::Range;

/// `ATH11K_FW_API2_FILE`.
pub const ATH11K_FW_API2_FILE: &str = "firmware-2.bin";
/// `ATH11K_FIRMWARE_MAGIC` (the container also carries its NUL).
pub const ATH11K_FIRMWARE_MAGIC: &[u8] = b"QCOM-ATH11K-FW";

/// `enum ath11k_fw_ie_type`.
pub mod ie {
    pub const TIMESTAMP: u32 = 0;
    pub const FEATURES: u32 = 1;
    pub const AMSS_IMAGE: u32 = 2;
    pub const M3_IMAGE: u32 = 3;
}

/// `ATH11K_FW_FEATURE_COUNT`: `enum ath11k_fw_features` has no feature
/// yet, so the FEATURES IE never sets a bit.
pub const ATH11K_FW_FEATURE_COUNT: usize = 0;

/// `sizeof(struct ath11k_fw_ie)` (the header without `data[]`).
pub const FW_IE_HDR_LEN: usize = 8;

/// Why `ath11k_fw_request_firmware_api_n` rejected the file (all
/// `-EINVAL`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// "firmware image too small to contain magic".
    TooSmall(usize),
    /// "Invalid firmware magic".
    BadMagic,
    /// "No space for padding after magic".
    NoPadding,
    /// "Invalid length for FW IE %d (%zu < %zu)": `(id, left, ie_len)`.
    IeLength(u32, usize, usize),
}

impl FwError {
    /// Positive Linux errno.
    pub const fn errno(self) -> i32 {
        22 // -EINVAL
    }
}

/// What the IEs of a `firmware-N.bin` carried (Linux `ab->fw`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FwIes {
    /// "found fw timestamp" (a 4-byte TIMESTAMP IE).
    pub timestamp: Option<u32>,
    /// `ab->fw.fw_features` (bit `i` for `i < ATH11K_FW_FEATURE_COUNT`).
    pub features: u64,
    /// The FEATURES IE was present (its length, for the log).
    pub features_len: Option<usize>,
    /// `ab->fw.amss_data` / `amss_len` as a range of the file.
    pub amss: Option<Range<usize>>,
    /// `ab->fw.m3_data` / `m3_len` as a range of the file.
    pub m3: Option<Range<usize>>,
    /// Ids of "Unknown FW IE" elements, in file order.
    pub unknown: Vec<u32>,
}

/// `ALIGN(x, 4)`.
const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The FEATURES IE loop: bit `i` of the IE (byte `i / 8`, bit `i % 8`)
/// for `i < count`, stopping at the end of the IE (`index == ie_len`).
pub fn feature_bits(ie: &[u8], count: usize) -> u64 {
    let mut bits = 0u64;
    let mut i = 0;
    while i < count.min(64) {
        let (index, bit) = (i / 8, i % 8);
        if index == ie.len() {
            break;
        }
        if ie[index] & (1 << bit) != 0 {
            bits |= 1 << i;
        }
        i += 1;
    }
    bits
}

/// The parse of `ath11k_fw_request_firmware_api_n`, element for element.
pub fn parse_api_n(file: &[u8]) -> Result<FwIes, FwError> {
    let mut len = file.len();
    // "magic also includes the null byte, check that as well"
    let mut magic_len = ATH11K_FIRMWARE_MAGIC.len() + 1;
    if len < magic_len {
        return Err(FwError::TooSmall(len));
    }
    if &file[..magic_len - 1] != ATH11K_FIRMWARE_MAGIC || file[magic_len - 1] != 0 {
        return Err(FwError::BadMagic);
    }
    // "jump over the padding"
    magic_len = align4(magic_len);
    // "make sure there's space for padding"
    if magic_len > len {
        return Err(FwError::NoPadding);
    }
    len -= magic_len;
    let mut at = magic_len;
    let mut out = FwIes::default();

    // "loop elements"
    while len > FW_IE_HDR_LEN {
        let ie_id = le32(file, at);
        let mut ie_len = le32(file, at + 4) as usize;
        len -= FW_IE_HDR_LEN;
        at += FW_IE_HDR_LEN;
        if len < ie_len {
            return Err(FwError::IeLength(ie_id, len, ie_len));
        }
        let data = at..at + ie_len;
        match ie_id {
            ie::TIMESTAMP => {
                if ie_len == 4 {
                    out.timestamp = Some(le32(file, at));
                }
            }
            ie::FEATURES => {
                out.features_len = Some(ie_len);
                out.features |= feature_bits(&file[data], ATH11K_FW_FEATURE_COUNT);
            }
            ie::AMSS_IMAGE => out.amss = Some(data),
            ie::M3_IMAGE => out.m3 = Some(data),
            other => out.unknown.push(other),
        }
        // "jump over the padding"
        ie_len = align4(ie_len);
        // "make sure there's space for padding"
        if ie_len > len {
            break;
        }
        len -= ie_len;
        at += ie_len;
    }
    Ok(out)
}

/// Linux `ab->fw` after `ath11k_fw_pre_init`: the API version, the
/// `firmware-N.bin` bytes (kept for the device's lifetime, as Linux keeps
/// `ab->fw.fw` until `ath11k_fw_destroy`) and what its IEs point at.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FwApi {
    /// `ab->fw.api_version`.
    pub api_version: u8,
    pub file: Vec<u8>,
    pub ies: FwIes,
}

impl FwApi {
    /// `ath11k_fw_pre_init`: `request` is `ath11k_core_firmware_request`
    /// for `ath11k/<dir>/<name>` (a positive errno when absent). Returns
    /// the result and, when the container was found but refused, why
    /// (Linux logs it and continues with API 1).
    pub fn pre_init(
        request: impl FnOnce(&str) -> Result<Vec<u8>, i32>,
    ) -> (FwApi, Option<FwError>) {
        let file = match request(ATH11K_FW_API2_FILE) {
            Ok(f) => f,
            Err(_) => return (Self::api1(), None),
        };
        match parse_api_n(&file) {
            Ok(ies) => (
                FwApi {
                    api_version: 2,
                    file,
                    ies,
                },
                None,
            ),
            // err: release_firmware(ab->fw.fw); ab->fw.fw = NULL.
            Err(e) => (Self::api1(), Some(e)),
        }
    }

    /// No `firmware-N.bin` (`api_version = 1`).
    pub fn api1() -> FwApi {
        FwApi {
            api_version: 1,
            ..FwApi::default()
        }
    }

    fn slice(&self, r: &Option<Range<usize>>) -> Option<&[u8]> {
        let r = r.as_ref()?;
        // `amss_data && amss_len > 0` / `m3_data && m3_len > 0`.
        (!r.is_empty()).then(|| &self.file[r.clone()])
    }

    /// The MHI image `ath11k_mhi_register` uses from the container
    /// (`None` = request `amss.bin`).
    pub fn amss(&self) -> Option<&[u8]> {
        self.slice(&self.ies.amss)
    }

    /// The M3 image `ath11k_qmi_m3_load` uses from the container
    /// (`None` = request `m3.bin`).
    pub fn m3(&self) -> Option<&[u8]> {
        self.slice(&self.ies.m3)
    }
}
