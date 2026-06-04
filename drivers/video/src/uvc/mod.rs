//! USB Video Class (UVC) webcam driver.
//!
//! Implements the full UVC bring-up pipeline from USB class 0x0E device
//! detection through descriptor parsing, probe/commit negotiation, isochronous
//! transfer scheduling, and frame reassembly.
//!
//! ## Module structure
//!
//! - [`descriptor`] — VC/VS class-specific descriptor parsing (VC_HEADER,
//!   INPUT/OUTPUT_TERMINAL, PROCESSING_UNIT, EXTENSION_UNIT, VS_FORMAT_*,
//!   VS_FRAME_*).
//! - [`control`] — UVC class request codes (GET_CUR/SET_CUR/…) and
//!   probe/commit payload encoding (26-byte and 34-byte variants).
//! - [`streaming`] — VS descriptor blob walker; produces `StreamFormat`
//!   lists used by the V4L2 surface.
//! - [`probe`] — USB class 0x0E detection; walks config descriptor to locate
//!   VC and VS interfaces and their class-specific descriptor blobs.
//! - [`payload`] — UVC payload header decoder (BFH byte) and frame
//!   reassembler (FID/EOF state machine).
//! - [`xfer`] — Isochronous transfer depth scheduler + bulk fallback.
//! - [`format`] — Pixel-format decoders (YUYV→RGBA, NV12→RGBA, MJPEG
//!   passthrough).
//!
//! ## References
//!
//! - USB Device Class Definition for Video Devices, Revision 1.5 (USB-IF,
//!   March 2012) — public specification.
//! - Linux GPL reference: `drivers/media/usb/uvc/` — consulted for
//!   algorithm structure after the 2026-05-20 GPL-2.0-or-later relicense.

pub mod control;
pub mod descriptor;
pub mod format;
pub mod payload;
pub mod probe;
pub mod streaming;
pub mod xfer;

// Re-export the most commonly used types.
pub use descriptor::{
    DescError, ExtensionUnit, FormatFrameBased, FormatMjpeg, FormatUncompressed, FrameFrameBased,
    FrameMjpeg, FrameUncompressed, InputTerminal, OutputTerminal, ProcessingUnit, SelectorUnit,
    VcHeader, VsInputHeader, CS_INTERFACE, GUID_FORMAT_NV12, GUID_FORMAT_YUY2, ITT_CAMERA,
    OTT_VENDOR_SPECIFIC, TT_STREAMING, USB_CLASS_VIDEO, USB_VIDEO_SUBCLASS_VIDEOCONTROL,
    USB_VIDEO_SUBCLASS_VIDEOSTREAMING, VC_EXTENSION_UNIT, VC_HEADER, VC_INPUT_TERMINAL,
    VC_OUTPUT_TERMINAL, VC_PROCESSING_UNIT, VC_SELECTOR_UNIT, VS_FORMAT_FRAME_BASED,
    VS_FORMAT_MJPEG, VS_FORMAT_UNCOMPRESSED, VS_FRAME_FRAME_BASED, VS_FRAME_MJPEG,
    VS_FRAME_UNCOMPRESSED, VS_INPUT_HEADER,
};

pub use control::{
    bm_request_type, w_index, w_value, ControlId, ControlRange, ProbeCommit,
    BM_REQUEST_TYPE_CLASS_IN, BM_REQUEST_TYPE_CLASS_OUT, GET_CUR, GET_DEF, GET_INFO, GET_LEN,
    GET_MAX, GET_MIN, GET_RES, PROBE_COMMIT_LEN_V10, PROBE_COMMIT_LEN_V15, PU_BRIGHTNESS_CONTROL,
    PU_CONTRAST_CONTROL, PU_GAIN_CONTROL, PU_SATURATION_CONTROL,
    PU_WHITE_BALANCE_TEMPERATURE_CONTROL, SET_CUR, VS_COMMIT_CONTROL, VS_PROBE_CONTROL,
};

pub use streaming::{
    flatten_formats, parse_streaming_descriptors, FormatDescriptor, FrameMode, PixelFmt,
    StreamFormat, StreamingError,
};

pub use probe::{is_video_interface, probe_uvc, EndpointInfo, ProbeError, UvcProbeResult};

pub use payload::{
    FrameReassembler, PayloadError, PayloadHeader, PushResult, BFH_EOF, BFH_EOH, BFH_ERR, BFH_FID,
    BFH_PTS, BFH_SCR, BFH_STI,
};

pub use xfer::{
    CompletedFrame, IsocScheduler, StreamHandle, StreamStats, TransferMode, ISOC_DEPTH,
    ISOC_PACKET_SIZE,
};

pub use format::{
    is_valid_mjpeg, nv12_frame_size, nv12_to_rgba, passthrough, yuyv_frame_size, yuyv_to_rgba,
    DecodedFrame,
};
