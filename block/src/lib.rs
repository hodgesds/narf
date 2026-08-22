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

#[cfg(feature = "cgroup")]
pub mod cgroup;
pub mod deadline;
pub mod encrypted;
pub mod fs_detect;
pub mod io_scheduler;
pub mod mq;
pub mod noop;
pub mod opal;
pub mod partition;
pub mod ram;
pub mod registry;
pub mod scsi;

mod e2e_tests;
mod tests;

pub use deadline::{DeadlineScheduler, Lane, STARVE_BOUND};
pub use io_scheduler::{
    bootstrap_io_scheduler_authority, current_io_scheduler_name, enqueue_on, install_io_scheduler,
    pick_next_on, reserve_io_scheduler_slot, BlockDeviceId, IoSched, IoSchedError, IoScheduler,
};
pub use mq::{MqDeadlineScheduler, MAX_LANES};
pub use noop::NoopScheduler;

#[cfg(feature = "cgroup")]
pub use cgroup::{dev_id_from_ptr, install_cgroup_io_hook, IoCgroupHook};
pub use registry::{
    block_device_count, block_devices, find_block_device, find_block_device_indexed,
    register_block_device, unregister_block_device, BlockDeviceSync, BlockIoError,
    RegisteredBlockDevice, SyncBlock,
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
    /// the completion. If it returns `Poll::Pending`, completion or device
    /// removal must wake the last supplied waker after publishing the result.
    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send;
    /// Ensure all previously-submitted writes are persistent on the media.
    /// Unsupported/no-op implementations resolve immediately; they must not
    /// return a permanently-pending future.
    fn flush(&self) -> impl Future<Output = ()> + Send;
    /// Advise the device that a range of blocks is no longer needed.
    fn discard(&self, range: LbaRange) -> impl Future<Output = ()> + Send;

    /// Cancel an in-flight request by kernel-assigned tag.
    fn cancel(&self, tag: u64) -> impl Future<Output = CancelResult> + Send;

    /// Submit a request and charge its bytes to the submitting task's
    /// cgroup-v2 `io` controller before dispatch.
    ///
    /// This is the cgroup-accounted submit seam. It reads the running
    /// task (`narf_scheduler::current_task_id`) in its synchronous
    /// prologue — the correct attribution point for every in-tree
    /// device, whose `submit` performs the transfer synchronously
    /// before the returned future is awaited (see `cgroup` module
    /// docs) — then delegates to [`BlockDevice::submit`].
    ///
    /// `dev` is the synthetic-but-stable MAJ:MIN id for this device
    /// (see [`crate::cgroup::dev_id_from_ptr`]); callers holding an
    /// `Arc<dyn BlockDeviceSync>` derive it from the device pointer.
    ///
    /// LIMITATION (accounting wiring): in-tree filesystems currently
    /// call [`BlockDevice::submit`] directly, so this accounted path
    /// is dormant until those call sites migrate to it. Migrating them
    /// touches the FS/driver crates (out of scope for the block-layer
    /// seam); this method is the single point they migrate *to*. No
    /// traffic is fabricated — only requests routed through here are
    /// charged.
    #[cfg(feature = "cgroup")]
    fn submit_accounted(
        &self,
        dev: u64,
        req: BlockRequest,
    ) -> impl Future<Output = BlockCompletion> + Send {
        // Charge in the synchronous prologue so `current_task_id` is
        // still the submitting task, then build the delegated future.
        let bytes = u64::from(req.blocks) * u64::from(self.logical_block_size());
        let is_write = matches!(
            req.op,
            BlockOp::Write { .. } | BlockOp::WriteZeroes | BlockOp::Trim
        );
        crate::cgroup::charge_io(dev, bytes, is_write);
        self.submit(req)
    }
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
