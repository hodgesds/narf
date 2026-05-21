//! narf-block — block device abstraction.
//!
//! Spec: `block/specification/spec.md`. Stage-3 subset: core `BlockDevice`
//! trait, request/completion types, and the I/O scheduler skeleton.
//!
//! # Purpose
//!
//! This crate defines the generic interface every block device (real or
//! virtual) implements, the I/O scheduler that orders requests across
//! consumers, and the types used for dispatch and completion.
//!
//! Stage-3 also lands a single-queue deadline I/O scheduler in
//! `deadline::DeadlineScheduler` — two FIFO lanes (read / write)
//! with write-starvation prevention and per-request deadline
//! promotion. Request merging, multi-queue dispatch, and
//! device-queue-depth back-pressure remain Stage-4 work.
//!
//! Non-goals for Stage 3:
//! - Multi-queue dispatch (Stage 4).
//! - Discard/TRIM (Stage 4).
//! - NVMe backing (Stage 4).
//! - Page cache (lives in `filesystem/`).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod deadline;
pub mod encrypted;
pub mod mq;
pub mod fs_detect;
pub mod opal;
pub mod partition;
pub mod sync_to_async;
pub mod ram;
pub mod registry;
pub mod scsi;

mod tests;

pub use deadline::{DeadlineScheduler, Lane, STARVE_BOUND};
pub use mq::{MqDeadlineScheduler, MAX_LANES};
pub use registry::{
    block_device_count, block_devices, find_block_device, register_block_device, BlockDeviceSync,
    BlockIoError, RegisteredBlockDevice, SyncBlock,
};

use core::future::Future;
use narf_capabilities::{Cap, Read};
use narf_io::DmaBuffer;

// ── BlockDevice trait ───────────────────────────────────────────────

/// Generic interface for block devices.
pub trait BlockDevice: Send + Sync {
    /// Logical block size in bytes (e.g. 512 or 4096).
    fn logical_block_size(&self) -> u32;
    /// Physical block size in bytes.
    fn physical_block_size(&self) -> u32;
    /// Total capacity in blocks.
    fn capacity_blocks(&self) -> u64;
    /// Check for optional feature support.
    fn supports(&self, feat: BlockFeature) -> bool;

    /// Submit a block I/O request. Returns a future that resolves to
    /// the completion.
    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send;
    /// Ensure all previously-submitted writes are persistent on the media.
    fn flush(&self) -> impl Future<Output = ()> + Send;
    /// Advise the device that a range of blocks is no longer needed.
    fn discard(&self, range: LbaRange) -> impl Future<Output = ()> + Send;

    /// Cancel an in-flight request by kernel-assigned tag.
    fn cancel(&self, tag: u64) -> impl Future<Output = CancelResult> + Send;
}

/// Optional block device features.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockFeature {
    Flush,
    Discard,
    WriteZeroes,
    Fua,
    Zoned,
    AtomicWrites,
}

/// Result of a cancellation request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CancelResult {
    /// Operation was aborted before hardware completed.
    Cancelled,
    /// Operation finished naturally; completion should be drained.
    Completed,
    /// Tag refers to no in-flight operation.
    NotFound,
}

// ── Request / Completion ───────────────────────────────────────────

/// A single block I/O request.
#[derive(Debug)]
pub struct BlockRequest {
    /// Operation type (Read, Write, etc.).
    pub op: BlockOp,
    /// Logical block address to start at.
    pub lba: u64,
    /// Number of blocks to transfer.
    pub blocks: u32,
    /// DMA buffer for the payload. Cap-gated; no copy in `block/`.
    /// Currently using `Read` as a placeholder; real rights are
    /// checked at the `BlockDevice::submit` invocation.
    pub buffer: Cap<DmaBuffer, Read>,
    /// Quality-of-service hint for the scheduler.
    pub qos: QosHint,
    /// Opaque cookie echoed back in the completion.
    pub user_tag: u64,
}

/// Block operation types.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockOp {
    Read,
    Write { fua: bool },
    WriteZeroes,
    Trim,
}

/// Quality of service hints for I/O scheduling.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QosHint {
    Latency,
    Throughput,
    Background,
}

/// Outcome of a block I/O request.
#[derive(Debug)]
pub struct BlockCompletion {
    /// Kernel-assigned unique tag for this request.
    pub tag: u64,
    /// Opaque cookie from the submission.
    pub user_tag: u64,
    /// Success or error code.
    pub result: Result<(), BlockError>,
}

// Block payloads cross IPC rings; the `DmaBuffer` reference is via
// a cap index + phys handle, not a raw pointer in-struct, so MTE
// retag is the trait's identity default.
impl narf_ipc::Retag for BlockRequest {}
impl narf_ipc::Retag for BlockCompletion {}

/// Possible block I/O errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    IOError,
    PermissionDenied,
    InvalidRange,
    DeviceRemoved,
    Cancelled,
}

/// A range of logical block addresses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LbaRange {
    pub start: u64,
    pub blocks: u64,
}
