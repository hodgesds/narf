//! Unified block-device registry.
//!
//! Adapter trait that lets the kernel address NVMe / virtio-blk-pci /
//! AHCI uniformly. The existing `BlockDevice` trait (in `lib.rs`)
//! returns `impl Future` per method, which makes it impossible to
//! type-erase behind a `dyn`-pointer for cross-driver dispatch.
//! `BlockDeviceSync` is the synchronous alternative — drivers
//! provide blocking read/write ops that the registry consumes.
//!
//! Per-driver adapters live in each driver crate; they wrap the
//! controller's existing read/write helpers.
//!
//! Identification:
//!   - `name` is a `'static str` set at registration time
//!     (`"nvme0"`, `"vblk0"`, `"sata0"` by convention).
//!   - The same driver can register multiple devices when it grows
//!     multi-device support.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// GPT type GUID assigned by the UEFI specification to an EFI System
/// Partition (ESP).  Kept in canonical on-disk GUID display order, matching
/// [`crate::partition::format_guid`].
pub const GPT_EFI_SYSTEM_PARTITION_TYPE_GUID: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockIoError {
    /// Caller asked for a range outside the device's capacity.
    OutOfRange,
    /// Buffer too small for the requested transfer.
    BufferTooSmall,
    /// Underlying driver error (transport-specific status code).
    DriverError,
    /// Device was removed / not bound.
    DeviceRemoved,
}

/// Synchronous block-device interface usable behind `dyn`.
pub trait BlockDeviceSync: Send + Sync {
    /// LBA size in bytes (typically 512 or 4096).
    fn lba_size(&self) -> u32;
    /// Total capacity in LBAs.
    fn capacity(&self) -> u64;
    /// Read `n_blocks` LBAs starting at `lba` into `out`.
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError>;
    /// Write `n_blocks` LBAs starting at `lba` from `data`.
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError>;
}

/// Optional per-partition metadata attached to a registered block
/// device. `None` for whole-disk entries (e.g. `nvme0`); `Some` for
/// per-partition entries the partition scanner registered
/// (`nvme0p1`, `usb-msc0p2`, ...).
#[derive(Clone, Debug, Default)]
pub struct PartitionMetadata {
    /// GPT partition-type GUID in canonical 8-4-4-4-12 hex. Empty for MBR
    /// partitions and whole-disk entries.  Consumers use this semantic type
    /// rather than a device name or partition label to identify an ESP.
    pub gpt_type_guid: alloc::string::String,
    /// UTF-8 partition name decoded from the GPT entry's UTF-16LE
    /// `partition_name` field. Empty for MBR partitions (which have
    /// no name slot) and for whole-disk entries.
    pub partlabel: alloc::string::String,
    /// Per-partition GUID in canonical 8-4-4-4-12 hex. Empty for
    /// MBR partitions (which have no GUID).
    pub partuuid: alloc::string::String,
    /// Filesystem volume UUID discovered from the partition's on-disk
    /// superblock or boot record. Empty when the format is unknown or does
    /// not carry a UUID. This backs Linux's `/dev/disk/by-uuid` aliases.
    pub fs_uuid: alloc::string::String,
}

impl PartitionMetadata {
    /// True exactly for a GPT EFI System Partition, independent of its name,
    /// registration order, or filesystem volume UUID.
    pub fn is_efi_system_partition(&self) -> bool {
        self.gpt_type_guid
            .eq_ignore_ascii_case(GPT_EFI_SYSTEM_PARTITION_TYPE_GUID)
    }
}

/// One registered block device.
#[derive(Clone)]
pub struct RegisteredBlockDevice {
    pub name: &'static str,
    pub dev: Arc<dyn BlockDeviceSync>,
    /// GPT metadata, if this entry is a partition. `None` for
    /// whole-disk parents and for legacy-MBR partitions.
    pub partition: Option<PartitionMetadata>,
}

impl core::fmt::Debug for RegisteredBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisteredBlockDevice")
            .field("name", &self.name)
            .field("partition", &self.partition)
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<RegisteredBlockDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Register a block device. Idempotent on `name` — re-registering
/// replaces the prior entry so a driver can re-bring-up itself
/// without doubling its registry footprint.
pub fn register_block_device(name: &'static str, dev: Arc<dyn BlockDeviceSync>) {
    register_block_device_with_meta(name, dev, None);
}

/// Register a block device with GPT partition metadata attached.
/// Used by the partition scanner when it walks a GPT and finds
/// per-partition labels / GUIDs. Boot-time `root=PARTLABEL=` /
/// `root=PARTUUID=` selectors match against this metadata.
pub fn register_block_device_with_meta(
    name: &'static str,
    dev: Arc<dyn BlockDeviceSync>,
    partition: Option<PartitionMetadata>,
) {
    {
        let mut g = REGISTRY.lock();
        let entry = RegisteredBlockDevice {
            name,
            dev,
            partition,
        };
        if let Some(pos) = g.iter().position(|e| e.name == name) {
            g[pos] = entry;
        } else {
            g.push(entry);
        }
    }
    // Wave G: pair every registered device with a default
    // `IoScheduler` slot (boxed `DeadlineScheduler`). Reservation is
    // idempotent on `name` — a second `register_block_device` for
    // the same name resets the policy to the default, matching the
    // entry-replace semantics above. A driver that installed a
    // non-default policy must re-`install_io_scheduler` after
    // re-bring-up.
    crate::io_scheduler::reserve_io_scheduler_slot(name);
}

/// Snapshot of currently-registered block devices.
pub fn block_devices() -> Vec<RegisteredBlockDevice> {
    REGISTRY.lock().clone()
}

/// Number of registered block devices.
pub fn block_device_count() -> usize {
    REGISTRY.lock().len()
}

/// Look up a device by name.
pub fn find_block_device(name: &str) -> Option<Arc<dyn BlockDeviceSync>> {
    find_block_device_indexed(name).map(|(_, dev)| dev)
}

/// Look up a device by name together with its registration-order index.
///
/// The index is the Linux block-device minor used by `devfs`. Both values are
/// captured under one registry lock, so a concurrent hot-unplug cannot pair a
/// device with an index from a different registry state. Unlike
/// [`block_devices`], this targeted lookup does not allocate or clone an owned
/// registry snapshot; it clones only the matched device's [`Arc`].
pub fn find_block_device_indexed(name: &str) -> Option<(usize, Arc<dyn BlockDeviceSync>)> {
    REGISTRY
        .lock()
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.name == name)
        .map(|(index, entry)| (index, entry.dev.clone()))
}

/// Unregister a block device by name.  No-op if the name is not
/// present.  Used by hot-unplug paths and by test teardown.
pub fn unregister_block_device(name: &str) {
    let mut g = REGISTRY.lock();
    if let Some(pos) = g.iter().position(|e| e.name == name) {
        g.swap_remove(pos);
    }
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}

/// Test-only: snapshot the current registry so a test that wipes
/// it (e.g., `smoke_block_registry_register_find_round_trip`) can
/// restore the boot-time entries afterwards. Without this, later
/// tests that depend on `nvme0`/`vblk0`/`sata0` being present
/// (registered once at boot during driver probe) see an empty
/// registry and fail.
#[doc(hidden)]
pub fn __snapshot_for_test() -> Vec<RegisteredBlockDevice> {
    REGISTRY.lock().clone()
}

/// Test-only: restore a snapshot taken by `__snapshot_for_test`.
#[doc(hidden)]
pub fn __restore_for_test(snap: Vec<RegisteredBlockDevice>) {
    *REGISTRY.lock() = snap;
}

// ── Sync → Async block-device bridge ───────────────────────────────
//
// Filesystems consume `BlockDevice` (async); the registry stores
// `BlockDeviceSync`. `SyncBlock` adapts one to the other by running
// the sync read/write inside the future body — fine because every
// in-tree `BlockDeviceSync` (NVMe singleton, AHCI, RamBlockDevice's
// inherent path) does its own polling completion synchronously.
//
// The adapter resolves `BlockRequest::buffer` through
// `narf_io::resolve_cap`, copies bytes between the cap-bound DMA
// buffer and the sync trait's slice surface, and maps
// `BlockIoError` → `BlockError`. Single-PRP / single-allocation:
// the request is bounded by the DMA buffer the caller pre-mapped,
// so very large requests should split at the FS layer (or land via
// the native async driver path that doesn't need the bridge).

use core::future::Future;

use crate::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest, CancelResult,
    LbaRange,
};

/// Adapter: wrap any `Arc<dyn BlockDeviceSync>` and present the
/// async `BlockDevice` trait. Use this to feed registry-resident
/// devices (`block_devices()` results) to filesystem-mount helpers
/// that demand a `BlockDevice`.
#[derive(Clone)]
pub struct SyncBlock(pub Arc<dyn BlockDeviceSync>);

impl core::fmt::Debug for SyncBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncBlock")
            .field("lba_size", &self.0.lba_size())
            .field("capacity", &self.0.capacity())
            .finish_non_exhaustive()
    }
}

impl SyncBlock {
    pub fn new(dev: Arc<dyn BlockDeviceSync>) -> Arc<Self> {
        Arc::new(Self(dev))
    }
}

impl BlockDevice for SyncBlock {
    fn logical_block_size(&self) -> u32 {
        self.0.lba_size()
    }
    fn physical_block_size(&self) -> u32 {
        self.0.lba_size()
    }
    fn capacity_blocks(&self) -> u64 {
        self.0.capacity()
    }
    fn supports(&self, f: BlockFeature) -> bool {
        // Sync trait doesn't expose feature flags. Mirror what
        // RamBlockDevice exports (Flush + WriteZeroes are no-ops on
        // a sync transport, fine to advertise; the FS layer relies
        // on the call returning quickly more than on a hardware
        // doorbell).
        matches!(f, BlockFeature::Flush | BlockFeature::WriteZeroes)
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send {
        let buffer = narf_io::resolve_cap(&req.buffer);
        let result = self.do_io(&req, buffer);
        async move {
            BlockCompletion {
                tag: 0,
                user_tag: req.user_tag,
                result,
            }
        }
    }
    async fn flush(&self) {}
    async fn discard(&self, _r: LbaRange) {}
    async fn cancel(&self, _t: u64) -> CancelResult {
        CancelResult::NotFound
    }
}

impl SyncBlock {
    fn do_io(
        &self,
        req: &BlockRequest,
        buffer: Option<Arc<narf_io::DmaBuffer>>,
    ) -> Result<(), BlockError> {
        let buffer = buffer.ok_or(BlockError::PermissionDenied)?;
        let blocks = u16::try_from(req.blocks).map_err(|_| BlockError::InvalidRange)?;
        if blocks == 0 {
            return Ok(());
        }
        let lba_bytes = self.0.lba_size() as usize;
        let total = (blocks as usize)
            .checked_mul(lba_bytes)
            .ok_or(BlockError::InvalidRange)?;
        if buffer.len() < total {
            return Err(BlockError::InvalidRange);
        }
        // SAFETY: identity-mapped DMA bytes (see DmaBuffer doc),
        // exclusive for the duration of this synchronous IO.
        // SAFETY: Valid memory or trusted environment
        let slice = unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr(), total) };
        let map_err = |e: BlockIoError| match e {
            BlockIoError::OutOfRange => BlockError::InvalidRange,
            BlockIoError::BufferTooSmall => BlockError::InvalidRange,
            BlockIoError::DeviceRemoved => BlockError::DeviceRemoved,
            BlockIoError::DriverError => BlockError::IOError,
        };
        match req.op {
            BlockOp::Read => self.0.read(req.lba, blocks, slice).map_err(map_err),
            BlockOp::Write { fua: _ } => self.0.write(req.lba, blocks, slice).map_err(map_err),
            BlockOp::WriteZeroes => {
                for b in slice.iter_mut() {
                    *b = 0;
                }
                self.0.write(req.lba, blocks, slice).map_err(map_err)
            }
            BlockOp::Trim => Ok(()),
        }
    }
}
