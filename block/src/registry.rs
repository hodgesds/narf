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
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8])
        -> Result<(), BlockIoError>;
    /// Write `n_blocks` LBAs starting at `lba` from `data`.
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8])
        -> Result<(), BlockIoError>;
}

/// One registered block device.
#[derive(Clone)]
pub struct RegisteredBlockDevice {
    pub name: &'static str,
    pub dev:  Arc<dyn BlockDeviceSync>,
}

impl core::fmt::Debug for RegisteredBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisteredBlockDevice")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<RegisteredBlockDevice>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a block device. Idempotent on `name` — re-registering
/// replaces the prior entry so a driver can re-bring-up itself
/// without doubling its registry footprint.
pub fn register_block_device(name: &'static str, dev: Arc<dyn BlockDeviceSync>) {
    let mut g = REGISTRY.lock();
    if let Some(pos) = g.iter().position(|e| e.name == name) {
        g[pos] = RegisteredBlockDevice { name, dev };
    } else {
        g.push(RegisteredBlockDevice { name, dev });
    }
}

/// Snapshot of currently-registered block devices.
pub fn block_devices() -> Vec<RegisteredBlockDevice> {
    REGISTRY.lock().clone()
}

/// Number of registered block devices.
pub fn block_device_count() -> usize { REGISTRY.lock().len() }

/// Look up a device by name.
pub fn find_block_device(name: &str) -> Option<Arc<dyn BlockDeviceSync>> {
    REGISTRY.lock().iter().find(|e| e.name == name).map(|e| e.dev.clone())
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}
