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

pub mod descriptor;
pub mod control;
pub mod streaming;
pub mod probe;
pub mod payload;
pub mod xfer;
pub mod format;

// Re-export the most commonly used types.
pub use descriptor::{
    USB_CLASS_VIDEO,
    USB_VIDEO_SUBCLASS_VIDEOCONTROL,
    USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
    CS_INTERFACE,
    VC_HEADER, VC_INPUT_TERMINAL, VC_OUTPUT_TERMINAL,
    VC_SELECTOR_UNIT, VC_PROCESSING_UNIT, VC_EXTENSION_UNIT,
    VS_INPUT_HEADER, VS_FORMAT_UNCOMPRESSED, VS_FRAME_UNCOMPRESSED,
    VS_FORMAT_MJPEG, VS_FRAME_MJPEG, VS_FORMAT_FRAME_BASED, VS_FRAME_FRAME_BASED,
    ITT_CAMERA, TT_STREAMING, OTT_VENDOR_SPECIFIC,
    GUID_FORMAT_YUY2, GUID_FORMAT_NV12,
    VcHeader, InputTerminal, OutputTerminal, SelectorUnit,
    ProcessingUnit, ExtensionUnit,
    FormatMjpeg, FrameMjpeg, FormatUncompressed, FrameUncompressed,
    FormatFrameBased, FrameFrameBased,
    VsInputHeader, DescError,
};

pub use control::{
    SET_CUR, GET_CUR, GET_MIN, GET_MAX, GET_RES, GET_LEN, GET_INFO, GET_DEF,
    PU_BRIGHTNESS_CONTROL, PU_CONTRAST_CONTROL, PU_SATURATION_CONTROL,
    PU_GAIN_CONTROL, PU_WHITE_BALANCE_TEMPERATURE_CONTROL,
    VS_PROBE_CONTROL, VS_COMMIT_CONTROL,
    BM_REQUEST_TYPE_CLASS_IN, BM_REQUEST_TYPE_CLASS_OUT,
    bm_request_type, w_value, w_index,
    ProbeCommit, ControlId, ControlRange,
    PROBE_COMMIT_LEN_V10, PROBE_COMMIT_LEN_V15,
};

pub use streaming::{PixelFmt, FrameMode, StreamFormat, FormatDescriptor,
                    parse_streaming_descriptors, flatten_formats, StreamingError};

pub use probe::{probe_uvc, UvcProbeResult, ProbeError, EndpointInfo, is_video_interface};

pub use payload::{PayloadHeader, PayloadError, FrameReassembler, PushResult,
                  BFH_FID, BFH_EOF, BFH_PTS, BFH_SCR, BFH_ERR, BFH_EOH, BFH_STI};

pub use xfer::{StreamHandle, TransferMode, CompletedFrame, StreamStats,
               IsocScheduler, ISOC_DEPTH, ISOC_PACKET_SIZE};

pub use format::{DecodedFrame, passthrough, yuyv_to_rgba, nv12_to_rgba,
                 is_valid_mjpeg, yuyv_frame_size, nv12_frame_size};
