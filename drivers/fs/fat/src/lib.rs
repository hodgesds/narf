//! FAT Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/fat/*` or LGPL FatFs
//! source was consulted while writing this crate; every layout, magic
//! number, and algorithm trace back to one of the public references
//! below. Per-file headers cite the specific section consulted.
//!
//! References (entire crate). Every source below is **freely
//! available** — no paywall, no signup, no NDA required to read or
//! redistribute:
//!
//! - Microsoft FAT File System Specification (FATGEN v1.03), the
//!   primary normative source. Direct PDF on Microsoft's CDN, no
//!   account required:
//!   <https://download.microsoft.com/download/7/0/3/70320475-7281-420b-8594-531a7bc86e42/fatgen103.pdf>
//! - UEFI Specification v2.10 §13.3 — "File System Format" — the
//!   profile required by EFI System Partitions. UEFI Forum
//!   publishes specs gratis:
//!   <https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#file-system-format>
//! - OSDev Wiki, "FAT" — algorithmic descriptions only (no code
//!   copied). Wiki content is CC-BY-SA 4.0:
//!   <https://wiki.osdev.org/FAT>
//! - Specs/research notes vendored in `specification/` and
//!   `research/` (this repository, project license).

#![no_std]

extern crate alloc;

pub mod bpb;
pub mod fat;
pub mod dir;
pub mod fsinfo;
pub mod volume;
pub mod node;

mod tests;

use alloc::sync::Arc;

use narf_block::BlockDevice;
use narf_capabilities::{Cap, Grant, Write};
use narf_filesystem::{registry, DirOps, FsError, FsInstance, MountPoint};
use narf_lib::id::DomainId;

/// Mount a FAT volume sitting on `device` and register it with the
/// global VFS at `path`. Bridges the `Arc<FatVolume<B>>` returned by
/// `FatVolume::mount` (which `FsInstance` is implemented on directly)
/// and `VfsRegistry::mount`'s by-value `F: FsInstance` parameter via
/// a thin newtype.
///
/// Failure modes:
/// - `FsError::Unsupported` — the BPB on sector 0 doesn't have the
///   `0xAA55` signature (i.e. not a FAT volume).
/// - `FsError::Io(_)` — the underlying `BlockDevice::submit` returned
///   an error before the mount could read enough sectors.
/// - `FsError::PermissionDenied` — `authority` is revoked or the
///   path is already mounted (mapped through from `VfsRegistry`).
pub async fn mount_fat<B: BlockDevice + 'static>(
    authority: &Cap<MountPoint, Grant>,
    path: &str,
    device: Arc<B>,
    domain: DomainId,
) -> Result<Cap<MountPoint, Write>, FsError> {
    let vol = volume::FatVolume::mount(device, domain).await?;
    registry().mount(authority, path, FatMount(vol))
}

/// `FsInstance` adapter that owns an `Arc<FatVolume<B>>`. Forwards
/// `root` / `name` through; the inner Arc keeps the volume alive
/// for as long as the VFS holds the mount, and any `Cap<MountPoint,_>`
/// derived dentry retains a path back to the live volume.
struct FatMount<B: BlockDevice + 'static>(Arc<volume::FatVolume<B>>);

impl<B: BlockDevice + 'static> FsInstance for FatMount<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        self.0.root()
    }
    fn name(&self) -> &str {
        self.0.name()
    }
}

/// FAT Version
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FatVersion {
    Fat12,
    Fat16,
    Fat32,
}

// ── Stage::Subsys factory registration ────────────────────────────
//
// Wires the FAT driver into narf_filesystem::root_mount so the
// boot path's auto-mount walker can construct a FatVolume from
// any `Arc<dyn BlockDeviceSync>` whose BPB detect_filesystem
// classified as `FsType::Fat`.
//
// Path:
//   register_fs_factory(FsType::Fat, fat_factory)
//   fat_factory(dev) wraps `dev` in `SyncBlock` → `BlockDevice`,
//     then block_on's `FatVolume::mount(async_dev, domain)`.
//
// Shape mirrors `narf_drivers_fs_ext2::ext_factory` — keep them
// aligned so the root-mount integration path stays uniform.

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "fat-fs-factory", || {
        narf_filesystem::root_mount::register_fs_factory(
            narf_block::fs_detect::FsType::Fat,
            fat_factory,
        );
        InitResult::Ok
    });
}

/// Factory for FsType::Fat. Wraps the sync block device in a
/// SyncBlock bridge, then block_on's the async mount path.
///
/// Errors bubble up unchanged so the root-mount walker can log the
/// reason and try the next candidate device.
fn fat_factory(
    dev: Arc<dyn narf_block::BlockDeviceSync>,
) -> Result<Arc<dyn FsInstance>, FsError> {
    use narf_block::SyncBlock;

    // SyncBlock::new returns Arc<SyncBlock> — exactly the
    // `Arc<B: BlockDevice>` shape FatVolume::mount expects.
    let async_dev = SyncBlock::new(dev);
    let vol = narf_scheduler::block_on(volume::FatVolume::mount(
        async_dev,
        DomainId::DRIVER_0,
    ))?;
    Ok(vol as Arc<dyn FsInstance>)
}
