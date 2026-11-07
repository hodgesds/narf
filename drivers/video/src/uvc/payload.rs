//! UVC payload header (§2.4.3.3) parser and frame reassembler.
//!
//! Every isochronous packet (and every bulk transfer in bulk-streaming
//! mode) from a UVC device begins with a UVC payload header. The first
//! byte is `bHeaderLength`; the second is `bmHeaderInfo` (Bit Field
//! Header — BFH) carrying FID, EOF, PTS, SCR and error flags. Optional
//! 4-byte PTS and 6-byte SCR follow before the compressed/raw video data.
//!
//! The header machine is SHARED across format classes: frame-based
//! formats (uncompressed, MJPEG, DV) and temporally-encoded formats
//! (H.264, VP8 — `VS_FORMAT_FRAME_BASED`) use this same §2.4.3.3
//! header; what differs by class is which BFH bits are REQUIRED
//! (§2.4.3.7: frame-based formats require FID, temporally-encoded
//! formats require EOF and the EOS slice marker). BFH D4 is the
//! payload-specific bit (core §2.4.3.3 Table 2-5) — it is NOT a
//! reserved bit — and D5 (STI) marks an intra-coded frame for
//! temporally-encoded formats.
//!
//! Stream-based formats (`VS_FORMAT_STREAM_BASED`, e.g. MPEG-2 TS)
//! carry their frame/segment boundaries IN-BAND (§2.4.3.7), so FID
//! and EOF are optional there — and the Stream Based Payload spec
//! §2.1 makes each bit meaningful only when the negotiated
//! `bmFramingInfo` says so (D0 = FID required, D1 = EOF may be
//! present; otherwise the bit is ignored and shall be zero). A
//! stream-based device that signals neither bit can therefore never
//! complete a frame under the FID/EOF machine, and the buffer would
//! grow unbounded. The completion rule for that case is the one the
//! spec itself names (§2.4.3.7): "buffer fullness alone" triggers
//! buffer completion — the reassembler completes a segment when the
//! accumulated payload reaches the negotiated `dwMaxVideoFrameSize`
//! (§4.3.1.1 Table 4-47: the maximum size of a single codec-specific
//! segment when framing is enabled; the sender must toggle FID at
//! least every `dwMaxVideoFrameSize` bytes). That same negotiated
//! size caps accumulation in every mode: a push that would overflow
//! it is clamped to the bound, the frame completes at the bound, and
//! the excess bytes are dropped and counted — the buffer can never
//! exceed `dwMaxVideoFrameSize`. (When framing is NOT enabled the
//! spec says `dwMaxVideoFrameSize` is ignored for stream-based
//! formats; the bound is then a host-chosen safety cap, not a
//! device-promised segment size — frames still complete at it by
//! buffer fullness, which is exactly the §2.4.3.7 fallback.)
//!
//! What this machine deliberately does NOT treat as a boundary:
//! short or empty transfers. The Stream Based Payload spec §2.2.1
//! explicitly allows empty (micro)frames mid-stream ("if, due to
//! timing considerations, no format-specific packets are available
//! over a period of one or more (micro)frames, those (micro)frames
//! shall be empty"), so a short transfer carries no frame-boundary
//! meaning for stream-based formats.
//!
//! References:
//! - UVC 1.5 §2.4.3.3 "Video and Still Image Payload Headers",
//!   tables 2-5 (Bit Field Header) and 2-6 (extended fields).
//! - UVC 1.5 §2.4.3.7 "Data Format Classes" (frame-based /
//!   stream-based / temporally-encoded framing requirements).
//! - UVC 1.5 §2.4.3.4 "Source Clock Reference and Presentation Time Stamp".
//! - USB-IF "Frame-Based Payload, Revision 1.5" (VS_FORMAT_FRAME_BASED
//!   / VS_FRAME_FRAME_BASED descriptors; the payload header itself is
//!   the §2.4.3.3 header above).
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
/// Payload-specific bit (UVC 1.5 §2.4.3.3 Table 2-5, D4): its meaning
/// is assigned by the individual payload specification, not by the
/// core spec. For temporally-encoded (frame-based) formats the header
/// carries the EOS slice marker (core §1.5 glossary; bmFramingInfo
/// §4.3.1.1); it is surfaced here without a second name because the
/// assignment itself lives in the companion Frame-Based Payload spec.
/// This bit is NOT reserved: a device may legitimately set it.
pub const BFH_PAYLOAD_SPECIFIC: u8 = 1 << 4;
/// Still Image marker — and, for temporally-encoded formats, the
/// intra-coded-frame marker (UVC 1.5 §2.4.3.3 Table 2-5, D5).
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

    /// D4 payload-specific bit (UVC 1.5 §2.4.3.3 Table 2-5). The
    /// reassembler does not act on it — frame completion is driven
    /// by FID/EOF — but it is decoded and surfaced so payload-specific
    /// consumers (e.g. the EOS slice marker for temporally-encoded
    /// formats) can observe it instead of it being silently dropped.
    pub fn payload_specific(&self) -> bool {
        self.bfh & BFH_PAYLOAD_SPECIFIC != 0
    }

    /// STI bit — Still Image marker.
    pub fn is_still_image(&self) -> bool {
        self.bfh & BFH_STI != 0
    }

    /// STI bit read as the temporally-encoded meaning: for
    /// frame-based (H.264/VP8) streams D5 marks an intra-coded frame
    /// (UVC 1.5 §2.4.3.3 Table 2-5, D5). Same bit as
    /// [`is_still_image`](Self::is_still_image); the name records
    /// which class semantics the caller is applying.
    pub fn is_intra_coded(&self) -> bool {
        self.bfh & BFH_STI != 0
    }
}

// ── Frame reassembler ────────────────────────────────────────────────

/// `bmFramingInfo` D0 (UVC 1.5 §4.3.1.1 Table 4-47): the FID field is
/// required in the payload header; the sender must toggle FID at
/// least every `dwMaxVideoFrameSize` bytes.
pub const FRAMING_FID: u8 = 0x01;
/// `bmFramingInfo` D1: the EOF field may be present in the payload
/// header. It is a device error to specify D1 without D0; the
/// reassembler tolerates it (EOF is still honoured) rather than
/// failing the stream.
pub const FRAMING_EOF: u8 = 0x02;

/// How a reassembler completes frames and bounds its buffer.
///
/// The default is the legacy frame-based machine: FID/EOF completion
/// with no bound. A stream-based stream configures the negotiated
/// `dwMaxVideoFrameSize` bound plus `bmFramingInfo`, so segments
/// complete on buffer fullness (UVC 1.5 §2.4.3.7) when the device
/// sends no usable FID/EOF. A frame-based stream may also configure
/// a bound: the FID/EOF machine is unchanged and the bound acts as a
/// safety net (length completion + cap) if EOF is lost.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReassemblyConfig {
    /// Negotiated `dwMaxVideoFrameSize` in bytes: the maximum frame
    /// (frame-based) or codec-specific segment (stream-based) size.
    /// 0 = unbounded (legacy behaviour: no length completion, no cap).
    pub max_frame_size: u32,
    /// True for `VS_FORMAT_STREAM_BASED` streams.
    pub stream_based: bool,
    /// Negotiated `bmFramingInfo` (D0 = FID required, D1 = EOF may be
    /// present). Consulted only when `stream_based` is true — for
    /// known frame-based formats the field is ignored (§4.3.1.1).
    pub framing_info: u8,
}

impl ReassemblyConfig {
    /// Stream-based configuration: complete on buffer fullness at
    /// `max_frame_size`, honour FID/EOF only per `framing_info`.
    pub fn stream_based(max_frame_size: u32, framing_info: u8) -> Self {
        Self {
            max_frame_size,
            stream_based: true,
            framing_info,
        }
    }

    /// Frame-based configuration with a bound: the FID/EOF machine
    /// plus length completion and the cap at `max_frame_size`.
    pub fn bounded(max_frame_size: u32) -> Self {
        Self {
            max_frame_size,
            stream_based: false,
            framing_info: 0,
        }
    }
}

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
/// Frame-based formats (uncompressed, MJPEG, DV) and
/// temporally-encoded formats (H.264, VP8 — `VS_FORMAT_FRAME_BASED`)
/// share this machine: the §2.4.3.3 header is identical, and frame
/// boundaries come from the FID toggle with EOF completion
/// (§2.4.3.7 requires FID for frame-based formats and EOF for
/// temporally-encoded ones). The payload-specific D4 bit and the
/// STI/intra-coded bit are decoded on the header but do not drive
/// completion — frames still complete at EOF.
///
/// Stream-based formats (`VS_FORMAT_STREAM_BASED`) use the same
/// machine with a [`ReassemblyConfig`]: FID/EOF are honoured only
/// when the negotiated `bmFramingInfo` says they are meaningful,
/// and a segment completes when the accumulated payload reaches the
/// negotiated `dwMaxVideoFrameSize` (buffer-fullness completion,
/// §2.4.3.7) — so a stream that signals neither bit still completes
/// frames instead of growing the buffer without bound. The bound
/// also caps accumulation in every mode (see [`push`](Self::push)).
///
/// Linux equivalent: the state maintained by `struct uvc_buffer` +
/// `uvc_video_decode_start()` / `uvc_video_decode_data()` in
/// `uvc_video.c`. The FID flip is detected at the top of
/// `uvc_video_decode_start()` (around line 520); every copy on the
/// decode path is bounded by the buffer length.
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
    /// Completion / cap configuration (default: legacy FID/EOF
    /// machine, unbounded).
    pub config: ReassemblyConfig,
    /// Payload bytes dropped because a push would have grown the
    /// buffer past `config.max_frame_size` (0 when unbounded).
    pub bytes_dropped_overflow: u64,
}

impl FrameReassembler {
    pub fn new() -> Self {
        Self::with_config(ReassemblyConfig::default())
    }

    /// Build a reassembler with an explicit completion/cap config.
    pub fn with_config(config: ReassemblyConfig) -> Self {
        Self {
            buffer: Vec::new(),
            current_fid: false,
            frame_errored: false,
            frames_completed: 0,
            frames_dropped: 0,
            config,
            bytes_dropped_overflow: 0,
        }
    }

    /// Feed one ISO / bulk packet into the reassembler.
    ///
    /// The packet must include the UVC payload header at offset 0.
    ///
    /// Completion, in order: a meaningful EOF; the accumulation
    /// reaching `config.max_frame_size` (buffer-fullness completion,
    /// the stream-based rule when the device signals no boundary);
    /// a meaningful FID flip, which drops any partial frame and
    /// starts a new one. When a bound is configured the append is
    /// clamped to the remaining room: the buffer never exceeds
    /// `max_frame_size`, the frame completes at the bound, and the
    /// excess bytes of that packet are dropped (counted in
    /// `bytes_dropped_overflow`) — they belong to no frame the
    /// reassembler can attribute once the packet boundary is lost.
    pub fn push(&mut self, packet: &[u8]) -> PushResult {
        let (hdr, payload_off) = match PayloadHeader::decode(packet) {
            Ok(p) => p,
            Err(_) => return PushResult::Skipped,
        };

        let payload = &packet[payload_off..];
        // In stream-based mode FID/EOF are meaningful only when the
        // negotiated bmFramingInfo says so (Stream Based Payload 1.5
        // §2.1; core §4.3.1.1). For known frame-based formats the
        // field is ignored, so both bits are always meaningful there.
        let fid_meaningful =
            !self.config.stream_based || self.config.framing_info & FRAMING_FID != 0;
        let eof_meaningful =
            !self.config.stream_based || self.config.framing_info & FRAMING_EOF != 0;
        let fid_flipped = fid_meaningful && hdr.fid() != self.current_fid;

        if fid_flipped {
            // New frame detected — drop any partial accumulation.
            self.buffer.clear();
            self.frame_errored = false;
            self.current_fid = hdr.fid();
        }
        if hdr.is_error() {
            self.frame_errored = true;
        }
        let room = if self.config.max_frame_size == 0 {
            payload.len()
        } else {
            (self.config.max_frame_size as usize).saturating_sub(self.buffer.len())
        };
        let take = payload.len().min(room);
        self.buffer.extend_from_slice(&payload[..take]);
        self.bytes_dropped_overflow += (payload.len() - take) as u64;

        let eof = eof_meaningful && hdr.is_eof();
        let full = self.config.max_frame_size != 0
            && self.buffer.len() >= self.config.max_frame_size as usize;
        if eof || full {
            if self.frame_errored {
                self.buffer.clear();
                self.frame_errored = false;
                self.frames_dropped += 1;
                return PushResult::Errored;
            }
            self.frames_completed += 1;
            return PushResult::FrameComplete;
        }
        if fid_flipped {
            return PushResult::FidReset;
        }
        PushResult::Appended
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
