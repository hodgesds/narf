//! Isochronous transfer scheduling and bulk endpoint fallback.
//!
//! This module manages the transfer ring for UVC streaming:
//! - Schedules `ISOC_DEPTH` isochronous IN transfers ahead of time.
//! - Falls back to bulk IN when no isochronous endpoint is present
//!   (common on virtual webcams and some low-cost UVC devices).
//! - Feeds received packets into a `FrameReassembler`.
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_video.c`
//! `uvc_video_start_streaming()` (around line 2150) — calls
//! `usb_submit_urb()` for N URBs ahead of time (the Linux UVC driver
//! uses 5 URBs by default, each with multiple packets). The number of
//! in-flight transfers mirrors the value of `UVC_URBS` = 5 in the
//! Linux driver.

use super::payload::{FrameReassembler, PushResult};
use alloc::vec::Vec;

// ── Transfer constants ───────────────────────────────────────────────

/// Number of isochronous transfers to keep in-flight at once.
///
/// Linux UVC driver uses `UVC_URBS = 5` (uvc_video.c). We use 4 here
/// as the xHCI layer queues transfers differently (one TRB per call
/// rather than scatter-gather URBs).
pub const ISOC_DEPTH: usize = 4;

/// Maximum packet buffer size per isochronous packet in bytes.
///
/// Calculated from the VS endpoint's `wMaxPacketSize`. UVC FS is
/// limited to 1023 B; HS can be up to 3072 B (3 × 1024); SS can be
/// up to 3072 B per burst. 3072 covers all cases.
pub const ISOC_PACKET_SIZE: usize = 3072;

// ── Streaming state ──────────────────────────────────────────────────

/// Transfer mode chosen at stream-start time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransferMode {
    /// Isochronous IN transfers via the VS alternate-setting endpoint.
    Isochronous,
    /// Bulk IN transfers (fallback for virtual cams / UVC bulk variant).
    Bulk,
}

/// Completed frame delivered via `StreamHandle::next_frame()`.
#[derive(Clone, Debug)]
pub struct CompletedFrame {
    /// Raw payload bytes (MJPEG, YUYV, NV12, H.264, …).
    pub data: Vec<u8>,
    /// Frame sequence number, incremented per delivered frame.
    pub sequence: u64,
}

/// Statistics accumulated during streaming.
#[derive(Copy, Clone, Debug, Default)]
pub struct StreamStats {
    /// Total packets received.
    pub packets_received: u64,
    /// Packets with parse errors (bad UVC header).
    pub packets_skipped: u64,
    /// Frames with BFH_ERR set (dropped).
    pub frames_errored: u64,
    /// Frames successfully delivered.
    pub frames_delivered: u64,
}

/// Streaming handle returned by `StreamEngine::start()`.
///
/// Holds the reassembler and a queue of completed frames waiting to
/// be consumed by `Camera::next_frame()`. At this layer there is no
/// async executor — the caller drives the engine via
/// `StreamEngine::poll()`.
#[derive(Debug)]
pub struct StreamHandle {
    pub mode: TransferMode,
    /// xHCI slot ID for the bound device.
    pub slot_id: u8,
    /// xHCI DCI of the streaming endpoint.
    pub dci: u8,
    /// Packet buffer for a single transfer.
    pub packet_buf: Vec<u8>,
    pub reassembler: FrameReassembler,
    /// Queue of completed frames not yet consumed.
    pub frame_queue: Vec<CompletedFrame>,
    pub stats: StreamStats,
}

impl StreamHandle {
    /// Create a streaming handle for the given slot/DCI pair.
    pub fn new(mode: TransferMode, slot_id: u8, dci: u8) -> Self {
        let mut packet_buf = Vec::new();
        packet_buf.resize(ISOC_PACKET_SIZE, 0u8);
        Self {
            mode,
            slot_id,
            dci,
            packet_buf,
            reassembler: FrameReassembler::new(),
            frame_queue: Vec::new(),
            stats: StreamStats::default(),
        }
    }

    /// Feed a received packet into the reassembler and collect any
    /// completed frames.
    ///
    /// Called by the upper layer after each successful transfer
    /// (isochronous or bulk). `packet` includes the UVC payload header.
    pub fn ingest_packet(&mut self, packet: &[u8]) {
        self.stats.packets_received += 1;
        match self.reassembler.push(packet) {
            PushResult::FrameComplete => {
                let data = self.reassembler.take_frame();
                let seq = self.reassembler.frames_completed;
                self.frame_queue.push(CompletedFrame {
                    data,
                    sequence: seq,
                });
                self.stats.frames_delivered += 1;
            }
            PushResult::Errored => {
                self.stats.frames_errored += 1;
            }
            PushResult::Skipped => {
                self.stats.packets_skipped += 1;
            }
            PushResult::Appended | PushResult::FidReset => {}
        }
    }

    /// Dequeue the oldest completed frame, if any.
    pub fn take_frame(&mut self) -> Option<CompletedFrame> {
        if self.frame_queue.is_empty() {
            None
        } else {
            Some(self.frame_queue.remove(0))
        }
    }

    /// Number of frames waiting in the queue.
    pub fn pending_frames(&self) -> usize {
        self.frame_queue.len()
    }
}

// ── Transfer scheduler ───────────────────────────────────────────────

/// Controls how many isochronous transfers are kept in-flight.
///
/// The NARF xHCI driver exposes `isoch_in(slot, dci, buf)` as a
/// single-shot async call. The scheduler fires `ISOC_DEPTH` calls
/// concurrently via a depth counter; each completion re-fills one slot.
///
/// Because we cannot `join!()` without an async executor available at
/// this layer, the scheduler is driven by repeated calls to `poll_once()`
/// from the V4L2 surface's `next_frame()` future.
#[derive(Debug)]
pub struct IsocScheduler {
    /// How many in-flight transfers are outstanding at this moment.
    pub in_flight: usize,
    /// Desired depth (default `ISOC_DEPTH`).
    pub depth: usize,
}

impl IsocScheduler {
    pub fn new() -> Self {
        Self {
            in_flight: 0,
            depth: ISOC_DEPTH,
        }
    }

    /// One scheduler slot has completed — decrement the in-flight counter.
    pub fn on_complete(&mut self) {
        if self.in_flight > 0 {
            self.in_flight -= 1;
        }
    }

    /// True iff we should launch another transfer to refill the pipeline.
    pub fn should_submit(&self) -> bool {
        self.in_flight < self.depth
    }

    /// Mark a new transfer as submitted.
    pub fn on_submit(&mut self) {
        self.in_flight += 1;
    }
}

impl Default for IsocScheduler {
    fn default() -> Self {
        Self::new()
    }
}
