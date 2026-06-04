//! UVC payload header (§2.4.3.3) parser and frame reassembler.
//!
//! Every isochronous packet (and every bulk transfer in bulk-streaming
//! mode) from a UVC device begins with a UVC payload header. The first
//! byte is `bHeaderLength`; the second is `bmHeaderInfo` (Bit Field
//! Header — BFH) carrying FID, EOF, PTS, SCR and error flags. Optional
//! 4-byte PTS and 6-byte SCR follow before the compressed/raw video data.
//!
//! References:
//! - UVC 1.5 §2.4.3.3 "Video and Still Image Payload Headers",
//!   table 2-12 (Bit Field Header).
//! - UVC 1.5 §2.4.3.4 "Source Clock Reference and Presentation Time Stamp".
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_video.c`
//! `uvc_video_decode_data()` (around line 590) and `uvc_video_decode_start()`
//! (around line 520) — decode BFH byte, detect FID flip, accumulate payload.

use alloc::vec::Vec;

// ── BFH bit positions ────────────────────────────────────────────────

/// Frame Identifier: toggles between consecutive frames.
pub const BFH_FID: u8 = 1 << 0;
/// End Of Frame: this payload is the last in the current frame.
pub const BFH_EOF: u8 = 1 << 1;
/// Presentation Time Stamp present: bytes 2–5 carry a 32-bit PTS.
pub const BFH_PTS: u8 = 1 << 2;
/// Source Clock Reference present: 6-byte SCR at the next offset.
pub const BFH_SCR: u8 = 1 << 3;
/// Reserved (must be zero per spec).
pub const BFH_RES: u8 = 1 << 4;
/// Still Image marker.
pub const BFH_STI: u8 = 1 << 5;
/// Error: payload contains an error; host should drop the current frame.
pub const BFH_ERR: u8 = 1 << 6;
/// End Of Header: set on every conformant payload (bit 7).
pub const BFH_EOH: u8 = 1 << 7;

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PayloadError {
    /// Buffer too short (< 2 bytes).
    Short,
    /// `bHeaderLength` < 2 or exceeds the buffer length.
    BadLength,
    /// PTS or SCR flag set but not enough header bytes remain.
    TruncatedHeader,
}

// ── Payload header ───────────────────────────────────────────────────

/// Decoded UVC payload header.
///
/// The host decodes one of these at the start of every isochronous
/// (or bulk) packet. The FID bit is the primary frame-boundary signal;
/// EOF confirms frame completion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Total header byte count (≥ 2).
    pub length: u8,
    /// Raw BFH byte.
    pub bfh: u8,
    /// Presentation Time Stamp, if BFH.PTS set.
    pub pts: Option<u32>,
    /// Source Clock Reference (bus_clock_32, sof_counter_11), if BFH.SCR set.
    pub scr: Option<(u32, u16)>,
}

impl PayloadHeader {
    /// Decode a UVC payload header from the start of `buf`.
    ///
    /// Returns `(header, payload_start_offset)` on success.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), PayloadError> {
        if buf.len() < 2 {
            return Err(PayloadError::Short);
        }
        let length = buf[0];
        if length < 2 || (length as usize) > buf.len() {
            return Err(PayloadError::BadLength);
        }
        let bfh = buf[1];
        let mut off = 2usize;

        let pts = if bfh & BFH_PTS != 0 {
            if off + 4 > length as usize {
                return Err(PayloadError::TruncatedHeader);
            }
            let v = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            off += 4;
            Some(v)
        } else {
            None
        };

        let scr = if bfh & BFH_SCR != 0 {
            if off + 6 > length as usize {
                return Err(PayloadError::TruncatedHeader);
            }
            let bus = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            // SCR SOF counter: 11 bits starting at byte off+4.
            let sof = (buf[off + 4] as u16) | (((buf[off + 5] & 0x07) as u16) << 8);
            Some((bus, sof))
        } else {
            None
        };

        Ok((
            Self {
                length,
                bfh,
                pts,
                scr,
            },
            length as usize,
        ))
    }

    /// FID bit — toggles between adjacent frames.
    pub fn fid(&self) -> bool {
        self.bfh & BFH_FID != 0
    }

    /// EOF bit — this is the last payload of the current frame.
    pub fn is_eof(&self) -> bool {
        self.bfh & BFH_EOF != 0
    }

    /// ERR bit — caller should discard the in-flight frame.
    pub fn is_error(&self) -> bool {
        self.bfh & BFH_ERR != 0
    }

    /// STI bit — Still Image marker.
    pub fn is_still_image(&self) -> bool {
        self.bfh & BFH_STI != 0
    }
}

// ── Frame reassembler ────────────────────────────────────────────────

/// Outcome returned by `FrameReassembler::push()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PushResult {
    /// Payload bytes appended; frame not yet complete.
    Appended,
    /// EOF seen on a clean frame — `take_frame()` will return the data.
    FrameComplete,
    /// EOF seen but the frame had errors — data discarded.
    Errored,
    /// Payload header couldn't be decoded — packet skipped.
    Skipped,
    /// FID flipped mid-accumulation without prior EOF — partial frame
    /// dropped, new frame started with this payload already appended.
    FidReset,
}

/// Reassembles UVC payloads into complete video frames.
///
/// Linux equivalent: the state maintained by `struct uvc_buffer` +
/// `uvc_video_decode_start()` / `uvc_video_decode_data()` in
/// `uvc_video.c`. The FID flip is detected at the top of
/// `uvc_video_decode_start()` (around line 520).
#[derive(Debug)]
pub struct FrameReassembler {
    /// Accumulation buffer for the current frame.
    pub buffer: Vec<u8>,
    /// FID bit of the frame currently being accumulated.
    pub current_fid: bool,
    /// `true` if any payload in this frame had BFH_ERR set.
    pub frame_errored: bool,
    /// Total completed (non-error) frames delivered since creation.
    pub frames_completed: u64,
    /// Total frames dropped due to error since creation.
    pub frames_dropped: u64,
}

impl FrameReassembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_fid: false,
            frame_errored: false,
            frames_completed: 0,
            frames_dropped: 0,
        }
    }

    /// Feed one ISO / bulk packet into the reassembler.
    ///
    /// The packet must include the UVC payload header at offset 0.
    pub fn push(&mut self, packet: &[u8]) -> PushResult {
        let (hdr, payload_off) = match PayloadHeader::decode(packet) {
            Ok(p) => p,
            Err(_) => return PushResult::Skipped,
        };

        let payload = &packet[payload_off..];
        let fid_flipped = hdr.fid() != self.current_fid;

        if fid_flipped {
            // New frame detected — drop any partial accumulation.
            self.buffer.clear();
            self.frame_errored = false;
            self.current_fid = hdr.fid();
            self.buffer.extend_from_slice(payload);
            if hdr.is_error() {
                self.frame_errored = true;
            }
            if hdr.is_eof() {
                if self.frame_errored {
                    self.buffer.clear();
                    self.frame_errored = false;
                    self.frames_dropped += 1;
                    return PushResult::Errored;
                }
                self.frames_completed += 1;
                return PushResult::FrameComplete;
            }
            return PushResult::FidReset;
        }

        // Same frame — accumulate.
        if hdr.is_error() {
            self.frame_errored = true;
        }
        self.buffer.extend_from_slice(payload);

        if hdr.is_eof() {
            if self.frame_errored {
                self.buffer.clear();
                self.frame_errored = false;
                self.frames_dropped += 1;
                return PushResult::Errored;
            }
            self.frames_completed += 1;
            PushResult::FrameComplete
        } else {
            PushResult::Appended
        }
    }

    /// Consume and return the reassembled frame buffer.
    ///
    /// Call only after `push()` returns `PushResult::FrameComplete`.
    /// Leaves the reassembler ready for the next frame.
    pub fn take_frame(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        core::mem::swap(&mut out, &mut self.buffer);
        out
    }
}

impl Default for FrameReassembler {
    fn default() -> Self {
        Self::new()
    }
}
