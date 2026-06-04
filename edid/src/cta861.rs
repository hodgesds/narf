//! CTA-861 EDID extension block — clean-room.
//!
//! References (public-only):
//! - CTA-861-G "A DTV Profile for Uncompressed High Speed Digital
//!   Interfaces" (Consumer Technology Association, 2016).
//!   §7.3 (CEA Extension Block layout), §7.5 (Data Block Collection),
//!   §7.5.1 (Video Data Block / SVD format), §7.5.2 (Audio Data Block /
//!   SAD format), §7.5.3 (Speaker Allocation Data Block),
//!   §7.5.4 (Vendor Specific Data Block / VSDB),
//!   §7.5.6 (Extended Tag Code Data Blocks).
//!   <https://standards.cta.tech/>
//! - HDMI Specification 1.4b §8.3.2 — HDMI VSDB IEEE OUI 0x000C03 and
//!   the byte layout that follows the OUI inside a CTA VSDB.
//!   <https://www.hdmi.org/spec/index>
//! - VESA E-EDID 1.4 — base block carries `extension_count` at offset
//!   126; each subsequent 128-byte block has tag 0x02 if it is a CTA
//!   extension.
//!   <https://vesa.org/vesa-standards/>
//!
//! No GPL Linux source consulted.
//!
//! ## Layout (CTA-861-G §7.3)
//!
//! ```text
//!   byte 0     extension tag = 0x02
//!   byte 1     revision (commonly 3)
//!   byte 2     DTL offset — offset of first DTD; 0 means "no DTDs and
//!              no Data Block Collection".
//!   byte 3     bits[7]    underscan  (1 = supports underscan)
//!              bits[6]    audio      (1 = supports basic audio)
//!              bits[5]    YCbCr 4:4:4
//!              bits[4]    YCbCr 4:2:2
//!              bits[3..0] number of native DTDs
//!   byte 4..(DTL-1)  Data Block Collection (var)
//!   byte DTL..126    Detailed Timing Descriptors (18 bytes each)
//!   byte 127         checksum (sum of full block ≡ 0 mod 256)
//! ```
//!
//! Each Data Block in the collection is led by a 1-byte header:
//!
//! ```text
//!   bits[7..5]   tag code
//!   bits[4..0]   length L (number of payload bytes that follow)
//! ```
//!
//! Tag codes (§7.5):
//!  - 1 = Audio Data Block (each SAD = 3 bytes)
//!  - 2 = Video Data Block (each SVD = 1 byte)
//!  - 3 = Vendor Specific Data Block (first 3 bytes = IEEE OUI, LE)
//!  - 4 = Speaker Allocation Data Block (3 bytes payload)
//!  - 7 = Use Extended Tag Code (next byte refines the type)

use alloc::vec::Vec;

use crate::{DetailedTiming, EdidError, EDID_BLOCK_SIZE};

/// Extension block tag for CTA-861.
pub const CTA_TAG: u8 = 0x02;

/// IEEE Registration Identifier for the HDMI Forum (HDMI 1.4b §8.3.2).
pub const HDMI_LICENSING_OUI: [u8; 3] = [0x03, 0x0C, 0x00];
/// IEEE OUI for HDMI Forum (HDMI 2.0+ adds this alongside 0x000C03).
pub const HDMI_FORUM_OUI: [u8; 3] = [0xD8, 0x5D, 0xC4];

// CTA Data Block tag codes (§7.5).
pub const CTA_TAG_AUDIO: u8 = 1;
pub const CTA_TAG_VIDEO: u8 = 2;
pub const CTA_TAG_VENDOR: u8 = 3;
pub const CTA_TAG_SPEAKER: u8 = 4;
pub const CTA_TAG_EXTENDED: u8 = 7;

/// Capability flags packed in extension byte 3 (§7.3).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CtaCaps(pub u8);

impl CtaCaps {
    pub const UNDERSCAN: CtaCaps = CtaCaps(0x80);
    pub const BASIC_AUDIO: CtaCaps = CtaCaps(0x40);
    pub const YCBCR_444: CtaCaps = CtaCaps(0x20);
    pub const YCBCR_422: CtaCaps = CtaCaps(0x10);

    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// One Short Video Descriptor (SVD). 1 byte: bit 7 = native flag,
/// bits 6..0 = VIC (Video Identification Code from CTA-861-G Tables 4..6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShortVideoDescriptor {
    pub vic: u8,
    pub native: bool,
}

impl ShortVideoDescriptor {
    pub fn parse(b: u8) -> Self {
        Self {
            vic: b & 0x7F,
            native: (b & 0x80) != 0,
        }
    }
}

/// One Short Audio Descriptor (SAD), 3 bytes (§7.5.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShortAudioDescriptor {
    /// Audio format code (1 = LPCM, 2 = AC-3, …, 15 = WMA Pro).
    pub format: u8,
    /// Max channels - 1 (1..=8).
    pub max_channels: u8,
    /// Bitmap of supported sample-rate flags.
    pub sample_rates: u8,
    /// Format-dependent third byte (LPCM bit-depths, codec bitrate, etc.).
    pub format_dep: u8,
}

impl ShortAudioDescriptor {
    pub fn parse(b: &[u8; 3]) -> Self {
        Self {
            format: (b[0] >> 3) & 0x0F,
            max_channels: (b[0] & 0x07) + 1,
            sample_rates: b[1],
            format_dep: b[2],
        }
    }
}

/// Speaker Allocation Data Block payload (§7.5.3, 3 bytes; we surface
/// only the spec-defined byte 0 bitmap, bytes 1..2 are reserved).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpeakerAllocation(pub u8);

impl SpeakerAllocation {
    pub const FL_FR: u8 = 1 << 0; // Front Left + Front Right
    pub const LFE: u8 = 1 << 1;
    pub const FC: u8 = 1 << 2; // Front Center
    pub const BL_BR: u8 = 1 << 3; // Back / Surround
    pub const BC: u8 = 1 << 4;
    pub const FLC_FRC: u8 = 1 << 5;
    pub const RLC_RRC: u8 = 1 << 6;
}

/// One discovered Vendor Specific Data Block (§7.5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorBlock {
    /// IEEE OUI in CTA storage order (LSB first).
    pub oui: [u8; 3],
    pub payload: Vec<u8>,
}

impl VendorBlock {
    pub fn is_hdmi_licensing(&self) -> bool {
        self.oui == HDMI_LICENSING_OUI
    }
    pub fn is_hdmi_forum(&self) -> bool {
        self.oui == HDMI_FORUM_OUI
    }
}

/// Decoded HDMI Licensing VSDB (HDMI 1.4b §8.3.2). Many fields are
/// optional and indicated by the `length` of the payload — we surface
/// the ones that are mandatory plus the source-physical-address.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HdmiVsdb {
    /// CEC Source Physical Address (4 nibbles, e.g. 0x1000 for "1.0.0.0").
    pub cec_phys_addr: u16,
}

impl HdmiVsdb {
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < 5 {
            return None;
        }
        // payload = [oui:3, phys_addr_hi, phys_addr_lo, ...]
        let cec_phys_addr = u16::from_be_bytes([payload[3], payload[4]]);
        Some(Self { cec_phys_addr })
    }
}

/// Top-level data-block enum returned by `iter_data_blocks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataBlock {
    Audio(Vec<ShortAudioDescriptor>),
    Video(Vec<ShortVideoDescriptor>),
    Vendor(VendorBlock),
    Speaker(SpeakerAllocation),
    /// Extended tag — first payload byte is the extended tag code.
    Extended {
        ext_tag: u8,
        payload: Vec<u8>,
    },
    /// Anything we didn't decode.
    Unknown {
        tag: u8,
        payload: Vec<u8>,
    },
}

/// One CTA-861 extension block, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtaExtension {
    pub revision: u8,
    pub caps: CtaCaps,
    pub native_dtd_count: u8,
    pub data_blocks: Vec<DataBlock>,
    pub detailed_timings: Vec<DetailedTiming>,
}

impl CtaExtension {
    /// Parse a 128-byte CTA-861 extension block.
    pub fn parse(buf: &[u8]) -> Result<Self, EdidError> {
        if buf.len() != EDID_BLOCK_SIZE {
            return Err(EdidError::BadLength);
        }
        if buf[0] != CTA_TAG {
            return Err(EdidError::BadHeader);
        }
        let sum = buf.iter().fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
        if sum & 0xFF != 0 {
            return Err(EdidError::BadChecksum);
        }
        let revision = buf[1];
        let dtd_offset = buf[2] as usize;
        let byte3 = buf[3];
        let caps = CtaCaps(byte3 & 0xF0);
        let native_dtd_count = byte3 & 0x0F;

        // Data Block Collection occupies bytes 4..dtd_offset. If
        // dtd_offset == 0, no DBC and no DTDs. If dtd_offset == 4,
        // empty DBC (DTDs start immediately).
        let mut data_blocks = Vec::new();
        if dtd_offset >= 4 && dtd_offset <= 127 {
            let mut p = 4;
            while p < dtd_offset {
                let header = buf[p];
                let tag = (header >> 5) & 0x07;
                let len = (header & 0x1F) as usize;
                p += 1;
                if p + len > dtd_offset {
                    // Malformed length — stop parsing further blocks.
                    break;
                }
                let payload = &buf[p..p + len];
                p += len;
                let block = match tag {
                    CTA_TAG_AUDIO => {
                        let mut sads = Vec::new();
                        for chunk in payload.chunks_exact(3) {
                            let arr: [u8; 3] = [chunk[0], chunk[1], chunk[2]];
                            sads.push(ShortAudioDescriptor::parse(&arr));
                        }
                        DataBlock::Audio(sads)
                    }
                    CTA_TAG_VIDEO => {
                        let mut svds = Vec::new();
                        for b in payload {
                            svds.push(ShortVideoDescriptor::parse(*b));
                        }
                        DataBlock::Video(svds)
                    }
                    CTA_TAG_VENDOR if payload.len() >= 3 => {
                        let oui = [payload[0], payload[1], payload[2]];
                        DataBlock::Vendor(VendorBlock {
                            oui,
                            payload: payload.to_vec(),
                        })
                    }
                    CTA_TAG_SPEAKER if !payload.is_empty() => {
                        DataBlock::Speaker(SpeakerAllocation(payload[0]))
                    }
                    CTA_TAG_EXTENDED if !payload.is_empty() => DataBlock::Extended {
                        ext_tag: payload[0],
                        payload: payload[1..].to_vec(),
                    },
                    other => DataBlock::Unknown {
                        tag: other,
                        payload: payload.to_vec(),
                    },
                };
                data_blocks.push(block);
            }
        }

        // Detailed Timings — start at dtd_offset, run until byte 126.
        // Each is 18 bytes; an all-zero descriptor terminates the list
        // (per §3.10.2 of E-EDID).
        let mut detailed_timings = Vec::new();
        if dtd_offset >= 4 && dtd_offset <= 126 {
            let mut p = dtd_offset;
            while p + 18 <= 127 {
                let slice: [u8; 18] = buf[p..p + 18].try_into().expect("len");
                if slice.iter().all(|b| *b == 0) {
                    break;
                }
                if slice[0] == 0 && slice[1] == 0 {
                    // Display Descriptor reused inside CTA extension —
                    // skip; we surface DTDs only here.
                    p += 18;
                    continue;
                }
                detailed_timings.push(DetailedTiming::parse(&slice));
                p += 18;
            }
        }

        Ok(Self {
            revision,
            caps,
            native_dtd_count,
            data_blocks,
            detailed_timings,
        })
    }

    /// Convenience: first HDMI Licensing VSDB if present.
    pub fn hdmi_vsdb(&self) -> Option<HdmiVsdb> {
        for b in &self.data_blocks {
            if let DataBlock::Vendor(v) = b {
                if v.is_hdmi_licensing() {
                    return HdmiVsdb::parse(&v.payload);
                }
            }
        }
        None
    }
}
