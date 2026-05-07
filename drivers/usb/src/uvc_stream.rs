//! UVC video / still-image payload header — clean-room.
//!
//! References (public-only):
//! - "Universal Serial Bus Device Class Definition for Video Devices,
//!   Revision 1.5" (March 16, 2012) — USB-IF. Public document.
//!   §2.4.3.3 Video and Still Image Payload Headers (Bit Field
//!   Header — BFH — encoding the FID toggle and EOF flags).
//!   Table 2-12 (Bit Field Header layout).
//!   §2.4.3.4 Source Clock Reference and Presentation Time Stamp
//!   (PTS / SCR optional fields).
//!   <https://www.usb.org/document-library/video-class-v15-document-set>
//! - UVC 1.5 Frame-Based Payload Specification (companion public
//!   document) — referenced for the payload-header convention reused
//!   on H.264 / VP8 / Frame-Based formats.
//!   <https://www.usb.org/document-library/video-class-v15-document-set>
//!
//! No GPL Linux source consulted.
//!
//! ## Payload header layout (§2.4.3.3, table 2-12)
//!
//! Each isochronous USB transaction starts with a small header:
//!
//! ```text
//!   byte 0  bHeaderLength — total header byte count (>= 2)
//!   byte 1  bmHeaderInfo (Bit Field Header):
//!     bit 0  Frame Identifier (FID) — toggles every new frame
//!     bit 1  End of Frame (EOF)
//!     bit 2  Presentation Time (PTS) — bytes 2..6 carry the PTS
//!     bit 3  Source Clock Reference (SCR) — 6 bytes carrying a
//!            32-bit SOF-tick + 11-bit clock-counter pair
//!     bit 4  Reserved
//!     bit 5  Still Image (SI)
//!     bit 6  Error
//!     bit 7  End of Header (EOH)
//! ```
//!
//! The payload follows the header bytes. EOH being set means the
//! header is complete (vendor extensions can append bytes inside
//! `bHeaderLength` only; the host stops parsing flag bits at this
//! header).

use alloc::vec::Vec;

// ── Bit Field Header bits (table 2-12) ─────────────────────────────

pub const BFH_FRAME_ID: u8 = 1 << 0;
pub const BFH_END_OF_FRAME: u8 = 1 << 1;
pub const BFH_PTS: u8 = 1 << 2;
pub const BFH_SCR: u8 = 1 << 3;
// bit 4 reserved
pub const BFH_STILL_IMAGE: u8 = 1 << 5;
pub const BFH_ERROR: u8 = 1 << 6;
pub const BFH_END_OF_HEADER: u8 = 1 << 7;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UvcStreamError {
    Short,
    /// `bHeaderLength` is < 2 (must include at least header-length
    /// + bmHeaderInfo).
    BadLength,
}

/// Decoded UVC payload header (§2.4.3.3).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Total header byte count.
    pub header_length: u8,
    pub frame_id: bool,
    pub end_of_frame: bool,
    pub still_image: bool,
    pub error: bool,
    pub end_of_header: bool,
    /// 32-bit Presentation Time Stamp (only valid when `pts == true`).
    pub pts: Option<u32>,
    /// 32-bit SOF-tick + 11-bit clock counter (only valid when `scr == true`).
    pub scr: Option<(u32, u16)>,
}

impl PayloadHeader {
    /// Build a Bit-Field Header byte from this header's flags.
    pub fn bfh(&self) -> u8 {
        let mut v = 0u8;
        if self.frame_id {
            v |= BFH_FRAME_ID;
        }
        if self.end_of_frame {
            v |= BFH_END_OF_FRAME;
        }
        if self.pts.is_some() {
            v |= BFH_PTS;
        }
        if self.scr.is_some() {
            v |= BFH_SCR;
        }
        if self.still_image {
            v |= BFH_STILL_IMAGE;
        }
        if self.error {
            v |= BFH_ERROR;
        }
        if self.end_of_header {
            v |= BFH_END_OF_HEADER;
        }
        v
    }

    /// Encode the header to wire bytes — `bHeaderLength` is set so
    /// the buffer length matches the encoded width.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        let bfh = self.bfh();
        let mut total = 2usize;
        if (bfh & BFH_PTS) != 0 {
            total += 4;
        }
        if (bfh & BFH_SCR) != 0 {
            total += 6;
        }
        out.push(total as u8);
        out.push(bfh);
        if let Some(pts) = self.pts {
            out.extend_from_slice(&pts.to_le_bytes());
        }
        if let Some((sof, clock)) = self.scr {
            out.extend_from_slice(&sof.to_le_bytes());
            // 11-bit clock-counter, low byte first.
            out.push((clock & 0xFF) as u8);
            out.push(((clock >> 8) & 0x07) as u8);
        }
        out
    }

    /// Decode a UVC payload header from the start of a transaction.
    /// Returns the header and the byte offset of the payload.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), UvcStreamError> {
        if buf.len() < 2 {
            return Err(UvcStreamError::Short);
        }
        let header_length = buf[0];
        if header_length < 2 || (header_length as usize) > buf.len() {
            return Err(UvcStreamError::BadLength);
        }
        let bfh = buf[1];
        let mut p = 2usize;
        let pts = if (bfh & BFH_PTS) != 0 {
            if p + 4 > header_length as usize {
                return Err(UvcStreamError::Short);
            }
            let v = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            Some(v)
        } else {
            None
        };
        let scr = if (bfh & BFH_SCR) != 0 {
            if p + 6 > header_length as usize {
                return Err(UvcStreamError::Short);
            }
            let sof = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            let clock = (buf[p + 4] as u16) | (((buf[p + 5] as u16) & 0x07) << 8);
            p += 6;
            Some((sof, clock))
        } else {
            None
        };

        Ok((
            Self {
                header_length,
                frame_id: (bfh & BFH_FRAME_ID) != 0,
                end_of_frame: (bfh & BFH_END_OF_FRAME) != 0,
                still_image: (bfh & BFH_STILL_IMAGE) != 0,
                error: (bfh & BFH_ERROR) != 0,
                end_of_header: (bfh & BFH_END_OF_HEADER) != 0,
                pts,
                scr,
            },
            header_length as usize,
        ))
    }
}

// ── Frame reassembler ──────────────────────────────────────────────

/// Tracks frame-id toggling so the host can detect frame boundaries
/// without losing a packet. The driver feeds each transaction's
/// header byte; the reassembler returns whether the FID flipped
/// (a new frame started) and whether End-of-Frame was set.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameReassembler {
    /// Most-recently-observed FID bit. `None` before the first packet.
    pub last_frame_id: Option<bool>,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameStep {
    pub new_frame: bool,
    pub end_of_frame: bool,
    pub error: bool,
}

impl FrameReassembler {
    pub fn feed(&mut self, header: PayloadHeader) -> FrameStep {
        let new_frame = match self.last_frame_id {
            Some(prev) => prev != header.frame_id,
            None => true,
        };
        self.last_frame_id = Some(header.frame_id);
        FrameStep {
            new_frame,
            end_of_frame: header.end_of_frame,
            error: header.error,
        }
    }
}
