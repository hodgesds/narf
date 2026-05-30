//! V4L2-equivalent userspace surface for UVC webcams.
//!
//! Provides a camera abstraction inspired by V4L2 (`videodev2.h`):
//! - `Camera::open()` — bind to a probed UVC device by index.
//! - `Camera::list_formats()` — enumerate supported pixel formats, resolutions,
//!   and frame rates.
//! - `Camera::set_format()` — negotiate format/frame via VS_PROBE_CONTROL →
//!   VS_COMMIT_CONTROL.
//! - `Camera::start_streaming()` / `stop_streaming()` — STREAMON / STREAMOFF.
//! - `Camera::next_frame()` — return the next complete reassembled frame.
//! - `Camera::set_control()` / `get_control()` — route PU/CT class requests.
//!
//! This is deliberately simpler than the full V4L2 IOCTL surface. There is no
//! user-space buffer mapping; buffers are kernel-owned and the caller
//! receives `Vec<u8>` copies on dequeue.
//!
//! Linux reference:
//! - `drivers/media/usb/uvc/uvc_v4l2.c` — `uvc_v4l2_do_ioctl()` handles
//!   VIDIOC_ENUM_FMT, VIDIOC_S_FMT, VIDIOC_STREAMON/OFF, VIDIOC_DQBUF.
//! - `drivers/media/usb/uvc/uvc_video.c` — `uvc_probe_video()` probe/commit
//!   negotiation loop.

use alloc::vec::Vec;
use crate::uvc::{
    ControlId, ControlRange, FormatDescriptor, PixelFmt,
    ProbeCommit, StreamFormat, StreamHandle, TransferMode,
    UvcProbeResult,
    flatten_formats, parse_streaming_descriptors,
};

// ── Error types ──────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CameraError {
    /// Device index out of range.
    NoSuchDevice,
    /// The requested format/resolution/fps is not supported by this device.
    UnsupportedFormat,
    /// Streaming not active; call `start_streaming()` first.
    NotStreaming,
    /// Streaming already active.
    AlreadyStreaming,
    /// USB control transfer failed.
    ControlFailed,
    /// No frame available yet.
    NoFrame,
    /// Driver not yet implemented at this layer.
    NotImplemented,
}

pub type Result<T> = core::result::Result<T, CameraError>;

// ── Negotiated stream parameters ─────────────────────────────────────

/// Parameters negotiated by the VS_PROBE / VS_COMMIT cycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StreamParams {
    /// 1-based format index selected by the device.
    pub format_index: u8,
    /// 1-based frame index selected by the device.
    pub frame_index: u8,
    /// Negotiated frame interval in 100 ns units.
    pub frame_interval: u32,
    /// Maximum video frame size in bytes (from GET_CUR(PROBE)).
    pub max_frame_size: u32,
    /// Maximum payload transfer size in bytes.
    pub max_payload_size: u32,
}

impl StreamParams {
    pub fn fps(&self) -> u32 {
        if self.frame_interval == 0 { 0 } else { 10_000_000 / self.frame_interval }
    }
}

// ── Camera handle ────────────────────────────────────────────────────

/// A live camera session.
///
/// Constructed by [`open_camera`] after a successful UVC probe + descriptor
/// parse + format enumeration. The handle owns the `StreamHandle` when
/// streaming is active.
#[derive(Debug)]
pub struct Camera {
    /// USB slot ID for this device (xHCI).
    pub slot_id: u8,
    /// VideoControl interface number.
    pub vc_interface: u8,
    /// VideoStreaming interface number.
    pub vs_interface: u8,
    /// Processing Unit ID (0 = none found).
    pub pu_unit_id: u8,
    /// Camera Terminal ID (0 = none found).
    pub ct_unit_id: u8,
    /// All supported stream formats.
    pub formats: Vec<StreamFormat>,
    /// Currently negotiated stream parameters (set after `set_format()`).
    pub params: Option<StreamParams>,
    /// Whether streaming is active.
    pub streaming: bool,
    /// Active streaming handle (present when `streaming == true`).
    pub stream_handle: Option<StreamHandle>,
    /// Probe result carrying endpoint info.
    pub probe_result: UvcProbeResult,
}

impl Camera {
    /// Create a Camera from a probe result and parsed formats.
    ///
    /// `pu_unit_id` and `ct_unit_id` are entity IDs extracted from the
    /// VC descriptor walk; pass 0 if not found.
    pub fn from_probe(
        slot_id: u8,
        probe_result: UvcProbeResult,
        pu_unit_id: u8,
        ct_unit_id: u8,
    ) -> Result<Self> {
        let formats = parse_streaming_descriptors(&probe_result.vs_cs_blob)
            .map_err(|_| CameraError::UnsupportedFormat)?;

        Ok(Self {
            slot_id,
            vc_interface: probe_result.vc_interface,
            vs_interface: probe_result.vs_interface,
            pu_unit_id,
            ct_unit_id,
            formats,
            params: None,
            streaming: false,
            stream_handle: None,
            probe_result,
        })
    }

    // ── Format enumeration ───────────────────────────────────────────

    /// List all supported formats, resolutions, and frame rates.
    ///
    /// V4L2 equivalent: VIDIOC_ENUM_FMT + VIDIOC_ENUM_FRAMESIZES +
    /// VIDIOC_ENUM_FRAMEINTERVALS.
    pub fn list_formats(&self) -> Vec<FormatDescriptor> {
        flatten_formats(&self.formats)
    }

    // ── Format negotiation ───────────────────────────────────────────

    /// Build a `ProbeCommit` for the requested format/frame/interval.
    ///
    /// Searches `self.formats` for a matching entry; returns
    /// `Err(UnsupportedFormat)` if none match.
    pub fn build_probe(&self, pixel_fmt: PixelFmt, width: u16, height: u16, fps: u32)
        -> Result<ProbeCommit>
    {
        let fmt = self.formats.iter()
            .find(|f| f.pixel_fmt == pixel_fmt)
            .ok_or(CameraError::UnsupportedFormat)?;

        let (frame_idx, interval) = fmt
            .find_frame(width, height, fps)
            .ok_or(CameraError::UnsupportedFormat)?;

        Ok(ProbeCommit {
            hint: 0x0001, // hint: frame_interval is significant
            format_index: fmt.format_index,
            frame_index: frame_idx,
            frame_interval: interval,
            ..ProbeCommit::default()
        })
    }

    /// Apply negotiated probe response to update stream parameters.
    ///
    /// Called after GET_CUR(PROBE) returns a device-adjusted response.
    pub fn apply_probe_response(&mut self, resp: &ProbeCommit) {
        self.params = Some(StreamParams {
            format_index: resp.format_index,
            frame_index: resp.frame_index,
            frame_interval: resp.frame_interval,
            max_frame_size: resp.max_video_frame_size,
            max_payload_size: resp.max_payload_transfer_size,
        });
    }

    // ── Streaming ────────────────────────────────────────────────────

    /// Begin streaming.
    ///
    /// Precondition: `set_format()` (i.e. probe/commit) must have been
    /// completed and `self.params` populated.
    ///
    /// V4L2 equivalent: VIDIOC_STREAMON.
    pub fn start_streaming(&mut self) -> Result<()> {
        if self.streaming {
            return Err(CameraError::AlreadyStreaming);
        }
        let _ = self.params.ok_or(CameraError::UnsupportedFormat)?;

        // Choose transfer mode based on available endpoints.
        let (mode, dci) = match (&self.probe_result.iso_in, &self.probe_result.bulk_in) {
            (Some(ep), _) => (TransferMode::Isochronous, ep.dci),
            (None, Some(ep)) => (TransferMode::Bulk, ep.dci),
            (None, None) => return Err(CameraError::NotImplemented),
        };

        self.stream_handle = Some(StreamHandle::new(mode, self.slot_id, dci));
        self.streaming = true;
        Ok(())
    }

    /// Stop streaming and drain the in-flight transfer ring.
    ///
    /// V4L2 equivalent: VIDIOC_STREAMOFF.
    pub fn stop_streaming(&mut self) -> Result<()> {
        if !self.streaming {
            return Err(CameraError::NotStreaming);
        }
        self.stream_handle = None;
        self.streaming = false;
        Ok(())
    }

    /// Feed a received USB packet into the streaming engine.
    ///
    /// The caller (USB interrupt handler or polling loop) calls this
    /// for every isochronous / bulk packet received from the device.
    /// Each packet must include the UVC payload header at offset 0.
    pub fn ingest_packet(&mut self, packet: &[u8]) -> Result<()> {
        let handle = self.stream_handle.as_mut().ok_or(CameraError::NotStreaming)?;
        handle.ingest_packet(packet);
        Ok(())
    }

    /// Return the next complete frame, if one is available.
    ///
    /// V4L2 equivalent: VIDIOC_DQBUF.
    ///
    /// Returns `Err(NoFrame)` when no complete frame has arrived yet.
    pub fn next_frame(&mut self) -> Result<crate::uvc::CompletedFrame> {
        let handle = self.stream_handle.as_mut().ok_or(CameraError::NotStreaming)?;
        handle.take_frame().ok_or(CameraError::NoFrame)
    }

    // ── Controls ─────────────────────────────────────────────────────

    /// Encode a SET_CUR request parameter block for a 2-byte signed
    /// integer control (brightness, contrast, gain, …).
    ///
    /// The caller submits this via `xhci.control_out()`:
    /// ```text
    ///   xhci.control_out(slot, BM_REQUEST_TYPE_CLASS_OUT, SET_CUR,
    ///                    w_value(selector), w_index(unit_id, vs_iface),
    ///                    &value_le16)
    /// ```
    ///
    /// V4L2 equivalent: VIDIOC_S_CTRL.
    pub fn encode_set_control(value: i16) -> [u8; 2] {
        value.to_le_bytes()
    }

    /// Return the `(unit_id, selector)` pair for a given ControlId.
    ///
    /// The caller uses these to build `w_value(selector)` and
    /// `w_index(unit_id, iface_num)` for the USB control transfer.
    pub fn control_routing(&self, id: ControlId) -> Result<(u8, u8)> {
        let (selector, is_ct) = id.selector_and_is_ct();
        let unit_id = if is_ct {
            if self.ct_unit_id == 0 { return Err(CameraError::UnsupportedFormat); }
            self.ct_unit_id
        } else {
            if self.pu_unit_id == 0 { return Err(CameraError::UnsupportedFormat); }
            self.pu_unit_id
        };
        Ok((unit_id, selector))
    }

    /// Decode a 2-byte GET_* response for an integer control.
    pub fn decode_control_i16(buf: &[u8]) -> Option<i16> {
        ControlRange::parse_i16(buf)
    }

    // ── Convenience accessors ─────────────────────────────────────────

    /// True if streaming is active.
    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// Currently negotiated parameters, if any.
    pub fn current_params(&self) -> Option<&StreamParams> {
        self.params.as_ref()
    }

    /// Streaming statistics (returns zeroes when not streaming).
    pub fn stats(&self) -> crate::uvc::StreamStats {
        self.stream_handle
            .as_ref()
            .map(|h| h.stats)
            .unwrap_or_default()
    }
}
