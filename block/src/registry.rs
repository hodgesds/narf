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
//!   - `name` is a `'static str` set at registration time, Linux-style
//!     (`"nvme0n1"`, `"vblk0"`, `"sata0"`; partitions append `p<N>`).
//!   - **A name is not an identity.** Names follow enumeration order
//!     (NVMe controllers are numbered in probe order, which is PCI order),
//!     so a disk that moves slot, or a controller that fails to probe,
//!     shifts every later name. Code that must find a specific disk matches
//!     on what the disk carries: a filesystem UUID or GPT PARTUUID
//!     ([`PartitionMetadata`], [`find_by_fs_uuid`], [`find_by_partuuid`])
//!     or the hardware identity ([`DiskIdentity`]: controller PCI address,
//!     model/serial, namespace EUI64/NGUID/UUID).

use alloc::string::String;
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
    /// Write refused: the device is read-only under the active
    /// [`crate::disk_policy`] (`narf.disks=boot-only`).
    ReadOnly,
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
    /// True when every [`Self::write`] would currently be refused (e.g. the
    /// device is read-only under [`crate::disk_policy`]). Filesystems consult
    /// it at mount time so a read-only device is mounted without any of the
    /// metadata repairs a writable mount performs. Wrappers must forward it.
    fn is_read_only(&self) -> bool {
        false
    }
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

/// Hardware identity of a disk, independent of its registry name.
///
/// Mirrors what Linux keeps per NVMe namespace head (`nvme_ns_head.ids`)
/// plus the controller identity udev's `60-persistent-storage.rules` reads
/// (`model`, `serial`, the PCI path). Partitions carry their disk's identity.
/// Fields a transport does not provide stay empty / `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskIdentity {
    /// Transport family (`"nvme"`, ...), the by-id prefix.
    pub transport: &'static str,
    /// Controller location, e.g. the PCI address `"0000:07:00.0"`.
    pub bus_path: String,
    /// Controller name (`"nvme1"`); like the block name, not an identity.
    pub controller: String,
    /// Model number, trimmed.
    pub model: String,
    /// Serial number, trimmed.
    pub serial: String,
    /// Firmware revision, trimmed.
    pub firmware: String,
    /// PCI vendor id of the controller (0 when unknown).
    pub vendor_id: u16,
    /// NVMe namespace id (0 for non-NVMe transports).
    pub nsid: u32,
    /// IEEE EUI-64 (NVMe Identify Namespace / NIDT 1).
    pub eui64: Option<[u8; 8]>,
    /// Namespace globally unique identifier (NIDT 2).
    pub nguid: Option<[u8; 16]>,
    /// Namespace UUID (NIDT 3).
    pub uuid: Option<[u8; 16]>,
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    use core::fmt::Write as _;
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// Canonical 8-4-4-4-12 lowercase form of a 16-byte UUID, as Linux `%pU`.
pub fn format_uuid_bytes(u: &[u8; 16]) -> String {
    let mut out = String::new();
    for (i, range) in [0..4, 4..6, 6..8, 8..10, 10..16].into_iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        push_hex(&mut out, &u[range]);
    }
    out
}

/// udev's `util_replace_whitespace` + `util_replace_chars`: trim, collapse
/// each whitespace run to one `_`, and replace anything outside udev's
/// allowed set with `_`.
fn udev_safe(s: &str) -> String {
    let mut out = String::new();
    let mut gap = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            gap = true;
            continue;
        }
        if gap {
            out.push('_');
            gap = false;
        }
        let ok = c.is_ascii_alphanumeric() || "#+-.:=@_".contains(c);
        out.push(if ok { c } else { '_' });
    }
    out
}

impl DiskIdentity {
    /// Linux `/sys/block/nvme*n*/wwid` (`wwid_show` in
    /// `drivers/nvme/host/core.c`): `uuid.<uuid>`, else `eui.<nguid>`, else
    /// `eui.<eui64>`, else the vendor/serial/model/nsid fallback.
    pub fn wwid(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        if let Some(u) = self.uuid {
            out.push_str("uuid.");
            out.push_str(&format_uuid_bytes(&u));
        } else if let Some(g) = self.nguid {
            out.push_str("eui.");
            push_hex(&mut out, &g);
        } else if let Some(e) = self.eui64 {
            out.push_str("eui.");
            push_hex(&mut out, &e);
        } else {
            let _ = write!(
                out,
                "nvme.{:04x}-{}-{}-{:08x}",
                self.vendor_id,
                udev_safe(&self.serial),
                udev_safe(&self.model),
                self.nsid
            );
        }
        out
    }

    /// `/dev/disk/by-id` names for the whole disk, as udev's
    /// `60-persistent-storage.rules` builds them for NVMe:
    /// `nvme-<model>_<serial>`, `nvme-<model>_<serial>_<nsid>` and
    /// `nvme-<wwid>`. Partitions append `-part<N>`. Empty when the
    /// transport has no model/serial.
    pub fn by_id_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.model.is_empty() && self.serial.is_empty() {
            return out;
        }
        let t = if self.transport.is_empty() {
            "disk"
        } else {
            self.transport
        };
        let base = alloc::format!("{t}-{}_{}", udev_safe(&self.model), udev_safe(&self.serial));
        if self.nsid != 0 {
            out.push(alloc::format!("{base}_{}", self.nsid));
        }
        out.push(base);
        if self.nsid != 0 {
            out.push(alloc::format!("{t}-{}", self.wwid()));
        }
        out
    }

    /// `/dev/disk/by-path` name: `pci-<bdf>-nvme-<nsid>` (udev
    /// `path_id`). `None` without a bus path.
    pub fn by_path_name(&self) -> Option<String> {
        if self.bus_path.is_empty() {
            return None;
        }
        Some(if self.nsid != 0 {
            alloc::format!("pci-{}-{}-{}", self.bus_path, self.transport, self.nsid)
        } else {
            alloc::format!("pci-{}", self.bus_path)
        })
    }
}

/// One registered block device.
#[derive(Clone)]
pub struct RegisteredBlockDevice {
    pub name: &'static str,
    /// Registry name of the whole disk, for a partition; `None` for a disk.
    pub parent: Option<&'static str>,
    /// Partition number (the `N` of `p<N>`), for a partition.
    pub partno: Option<u32>,
    /// Hardware identity of the disk (shared by its partitions), when the
    /// driver supplied one. See [`DiskIdentity`]; the name is not identity.
    pub identity: Option<Arc<DiskIdentity>>,
    /// The registered device behind its [`crate::disk_policy::PolicyGuard`].
    /// Every consumer of the registry writes through the guard.
    pub dev: Arc<dyn BlockDeviceSync>,
    /// Physical-disk identity shared by a disk and its partitions; the unit
    /// [`crate::disk_policy::trust_boot_medium`] trusts.
    pub disk: crate::disk_policy::DiskId,
    /// GPT metadata, if this entry is a partition. `None` for
    /// whole-disk parents and for legacy-MBR partitions.
    pub partition: Option<PartitionMetadata>,
}

impl core::fmt::Debug for RegisteredBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegisteredBlockDevice")
            .field("name", &self.name)
            .field("disk", &self.disk)
            .field("parent", &self.parent)
            .field("identity", &self.identity)
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
    register_entry(name, None, dev, partition, None);
}

/// Register a whole disk together with its hardware identity. Partitions
/// later registered under it ([`register_partition_device`]) inherit the
/// identity. The device is wrapped in the disk-policy guard like any other.
pub fn register_block_device_with_identity(
    name: &'static str,
    dev: Arc<dyn BlockDeviceSync>,
    identity: DiskIdentity,
) {
    register_entry(name, None, dev, None, Some(Arc::new(identity)));
}

/// Register partition `name` of the already-registered disk `parent_name`.
/// The partition shares the parent's [`crate::disk_policy::DiskId`], so the
/// write policy treats a disk and its partitions as one medium. An
/// unregistered parent gets a fresh identity (conservative: untrusted).
pub fn register_partition_device(
    name: &'static str,
    parent_name: &str,
    dev: Arc<dyn BlockDeviceSync>,
    partition: Option<PartitionMetadata>,
) {
    register_entry(name, Some(parent_name), dev, partition, None);
}

/// `N` of a `<parent>p<N>` (or `<parent><N>`, as `sda1`) partition name.
fn partno_from_name(name: &str, parent: &str) -> Option<u32> {
    let rest = name.strip_prefix(parent)?;
    let rest = rest.strip_prefix('p').unwrap_or(rest);
    rest.parse().ok()
}

fn register_entry(
    name: &'static str,
    parent_name: Option<&str>,
    dev: Arc<dyn BlockDeviceSync>,
    partition: Option<PartitionMetadata>,
    identity: Option<Arc<DiskIdentity>>,
) {
    {
        let mut g = REGISTRY.lock();
        let parent_entry = parent_name.and_then(|parent| g.iter().find(|e| e.name == parent));
        let disk = parent_entry
            .map(|e| e.disk)
            .unwrap_or_else(crate::disk_policy::new_disk_id);
        let parent = parent_entry.map(|e| e.name);
        let identity = identity.or_else(|| parent_entry.and_then(|e| e.identity.clone()));
        let partno = parent_name.and_then(|p| partno_from_name(name, p));
        // Every entry — disk or partition, any transport — is wrapped in the
        // `narf.disks` guard; nothing in the registry is reachable unguarded.
        let dev = Arc::new(crate::disk_policy::PolicyGuard::new(name, disk, dev))
            as Arc<dyn BlockDeviceSync>;
        let entry = RegisteredBlockDevice {
            name,
            parent,
            partno,
            identity,
            dev,
            disk,
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

/// Disk identity of the registered device `name`.
pub fn disk_of(name: &str) -> Option<crate::disk_policy::DiskId> {
    REGISTRY
        .lock()
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.disk)
}

/// Hardware identity of the registered device `name` (a partition reports
/// its disk's identity).
pub fn identity_of(name: &str) -> Option<Arc<DiskIdentity>> {
    REGISTRY
        .lock()
        .iter()
        .find(|entry| entry.name == name)
        .and_then(|entry| entry.identity.clone())
}

/// The registered device whose filesystem UUID is `uuid` (case-insensitive),
/// whatever its name. `None` when no entry, or more than one, carries it:
/// a duplicated UUID (a cloned disk) is ambiguous and must not be guessed.
/// (Members of one multi-device btrfs share an fsid; enumerate
/// [`block_devices`] to collect them.)
pub fn find_by_fs_uuid(uuid: &str) -> Option<RegisteredBlockDevice> {
    unique_match(|e| {
        e.partition
            .as_ref()
            .is_some_and(|p| !p.fs_uuid.is_empty() && p.fs_uuid.eq_ignore_ascii_case(uuid))
    })
}

/// The registered partition whose GPT PARTUUID is `partuuid`
/// (case-insensitive). `None` when absent or ambiguous.
pub fn find_by_partuuid(partuuid: &str) -> Option<RegisteredBlockDevice> {
    unique_match(|e| {
        e.partition
            .as_ref()
            .is_some_and(|p| !p.partuuid.is_empty() && p.partuuid.eq_ignore_ascii_case(partuuid))
    })
}

/// The registered whole disk with this hardware identity triple
/// (controller bus path + namespace id), e.g. `("0000:07:00.0", 1)`.
pub fn find_disk_by_bus_path(bus_path: &str, nsid: u32) -> Option<RegisteredBlockDevice> {
    unique_match(|e| {
        e.parent.is_none()
            && e.identity
                .as_ref()
                .is_some_and(|i| i.bus_path == bus_path && i.nsid == nsid)
    })
}

fn unique_match(pred: impl Fn(&RegisteredBlockDevice) -> bool) -> Option<RegisteredBlockDevice> {
    let g = REGISTRY.lock();
    let mut it = g.iter().filter(|e| pred(e));
    let first = it.next()?.clone();
    if it.next().is_some() {
        return None;
    }
    Some(first)
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
    fn is_read_only(&self) -> bool {
        self.0.is_read_only()
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
            BlockIoError::ReadOnly => BlockError::PermissionDenied,
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
