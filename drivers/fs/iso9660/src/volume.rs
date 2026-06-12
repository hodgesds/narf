//! ISO 9660 Volume management — descriptor walk, mount, sector I/O.
//!
//! Clean-room implementation. Volume layout, descriptor walk, and
//! cap-bound DMA wiring are derived strictly from the public
//! references below — no GPL/LGPL ISO 9660 source consulted.
//!
//! References:
//! - ECMA-119 §6.2.1 (System Area = first 16 sectors, ignored by
//!   the FS but reserved for boot loaders).
//! - ECMA-119 §6.2.2 (Data Area starts at logical sector 16, where
//!   the Volume Descriptor sequence begins).
//! - ECMA-119 §8 (Volume Descriptor sequence — walk forward from
//!   sector 16 until a Set Terminator is reached).
//! - ECMA-119 §9.1 (Directory Record layout — used here only to
//!   surface the root record from the PVD's embedded copy).
//! - OSDev Wiki, "ISO 9660".
//!   <https://wiki.osdev.org/ISO_9660>

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockError, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_filesystem::{DirOps, FsError, FsInstance};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use super::descriptor::{
    vd_type, PrimaryVolumeDescriptor, VolumeDescriptorHeader, STANDARD_IDENTIFIER,
};
use super::dir::{read_directory_record, DirectoryRecord};
use super::SECTOR_SIZE;

/// Cap → DmaBuffer pair owned by an `Iso9660Volume`. Minted once at
/// `mount()` via `narf_io::register_with_cap`; every sector read
/// derives a `Read` cap from this `Write` cap (per memory:
/// `Cap::bootstrap()` is forbidden in hot paths). Drop calls
/// `unregister`, releasing the registry slot and the underlying
/// frame.
#[derive(Debug)]
struct VolumeIo {
    cap: Cap<DmaBuffer, Write>,
}

impl VolumeIo {
    fn buffer(&self) -> Option<Arc<DmaBuffer>> {
        resolve_cap(&self.cap)
    }
}

impl Drop for VolumeIo {
    fn drop(&mut self) {
        unregister(self.cap);
    }
}

/// A mounted ISO 9660 volume.
#[derive(Debug)]
pub struct Iso9660Volume<B: BlockDevice> {
    pub device: Arc<B>,
    pub pvd: PrimaryVolumeDescriptor,
    pub domain: DomainId,
    pub self_weak: Weak<Iso9660Volume<B>>,
    /// Per-volume registered DMA scratch buffer + cap. See
    /// `VolumeIo` doc for why this is minted once at mount time.
    /// Held inside an `IrqSafeSpinLock` because every sector op
    /// holds it for a synchronous-copy span only and never across
    /// an `await` (the lock would otherwise deadlock under
    /// cooperative async).
    io: IrqSafeSpinLock<VolumeIo>,
}

impl<B: BlockDevice + 'static> Iso9660Volume<B> {
    /// Mount an ISO 9660 volume.
    ///
    /// Procedure (ECMA-119 §6.2.2 + §8):
    ///   1. The first 16 logical sectors (the "System Area") are
    ///      reserved for boot loaders and ignored by the FS.
    ///   2. Volume descriptors begin at sector 16. Walk forward
    ///      reading one sector at a time, stopping at the Set
    ///      Terminator (type 255). Capture the PVD (type 1).
    ///   3. The PVD embeds the root directory record at byte
    ///      offset 156 (a 34-byte field whose first byte is the
    ///      record's `length`).
    ///
    /// Requires `device.logical_block_size() == 2048` (the standard
    /// LBS, see `lib.rs` doc).
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        if device.logical_block_size() as usize != SECTOR_SIZE {
            return Err(FsError::Unsupported);
        }

        // Allocate + register the volume's per-mount scratch
        // buffer. Capacity: one logical sector. Mints exactly one
        // object-table slot for the lifetime of the volume.
        let buffer =
            alloc_coherent(SECTOR_SIZE, domain).map_err(|_| FsError::Io(BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap };

        let mut sector_buf = vec![0u8; SECTOR_SIZE];
        let mut pvd: Option<PrimaryVolumeDescriptor> = None;

        // §8 — walk forward from sector 16 until Set Terminator.
        // Cap the walk at a safety bound; a malformed image without
        // a terminator must not loop forever.
        const MAX_VD_WALK: u64 = 1024;
        let mut sector: u64 = 16;
        loop {
            if sector >= 16 + MAX_VD_WALK {
                break;
            }
            Self::read_sector_into(&*device, &io, sector, &mut sector_buf).await?;

            // SAFETY: VolumeDescriptorHeader is 7 bytes,
            // `#[repr(C, packed)]`, and the layout matches §8.1.
            // We just read a full 2048-byte sector into `sector_buf`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let header: VolumeDescriptorHeader = unsafe {
                core::ptr::read_unaligned(sector_buf.as_ptr() as *const VolumeDescriptorHeader)
            };

            if header.standard_identifier != STANDARD_IDENTIFIER {
                // Not a valid VD — unmountable.
                drop(io); // explicit drop runs `unregister`.
                return Err(FsError::Unsupported);
            }

            match header.vd_type {
                vd_type::PRIMARY => {
                    // SAFETY: PVD is `#[repr(C, packed)]`, exactly
                    // 2048 bytes (compile-time asserted in
                    // `descriptor.rs`), and the layout matches §8.4.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    let p: PrimaryVolumeDescriptor = unsafe {
                        core::ptr::read_unaligned(
                            sector_buf.as_ptr() as *const PrimaryVolumeDescriptor
                        )
                    };
                    pvd = Some(p);
                }
                vd_type::TERMINATOR => break,
                _ => {} // Boot Record / SVD / Partition — skipped.
            }

            sector += 1;
        }

        let pvd = pvd.ok_or(FsError::Unsupported)?;

        // Sanity-check the PVD's logical block size matches the
        // device. Real-world discs always report 2048 here; if
        // someone hands us a 512/1024-LBS PVD, we cannot serve it
        // through a 2048-LBS pipeline.
        if pvd.logical_block_size_le() as usize != SECTOR_SIZE {
            drop(io);
            return Err(FsError::Unsupported);
        }

        Ok(Arc::new_cyclic(|self_weak| Iso9660Volume {
            device,
            pvd,
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
        }))
    }

    /// Issue a one-sector read into `dst`. `dst` must be exactly
    /// [`SECTOR_SIZE`] bytes. Internally serialises on the volume's
    /// scratch buffer + cap; the cap is derived to `Read` for the
    /// submission and the source bytes are copied out under the
    /// spinlock.
    pub async fn read_sector(&self, lba: u64, dst: &mut [u8]) -> Result<(), FsError> {
        if dst.len() != SECTOR_SIZE {
            return Err(FsError::Io(BlockError::InvalidRange));
        }
        // Snapshot the cap (it's `Copy`); we cannot hold the
        // spinlock across the I/O await.
        let cap = { self.io.lock().cap };
        let req = BlockRequest {
            op: BlockOp::Read,
            lba,
            blocks: 1,
            buffer: cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        let completion = self.device.submit(req).await;
        completion.result.map_err(FsError::Io)?;

        let buf = self
            .io
            .lock()
            .buffer()
            .ok_or(FsError::Io(BlockError::PermissionDenied))?;
        // SAFETY: the registry holds the only `Arc<DmaBuffer>`
        // outside this clone; the volume serialises sector ops via
        // the outer spinlock so no other CPU/task is racing the
        // buffer bytes during this copy. Identity-mapped phys backs
        // the read.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), SECTOR_SIZE) };
        dst.copy_from_slice(src);
        Ok(())
    }

    /// `read_sector` variant usable before the `Arc<Iso9660Volume>`
    /// exists — `mount()` calls this through a `&VolumeIo` directly.
    async fn read_sector_into(
        device: &B,
        io: &VolumeIo,
        lba: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        if dst.len() != SECTOR_SIZE {
            return Err(FsError::Io(BlockError::InvalidRange));
        }
        let req = BlockRequest {
            op: BlockOp::Read,
            lba,
            blocks: 1,
            buffer: io
                .cap
                .derive::<Read>()
                .map_err(|_| FsError::Io(BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        let completion = device.submit(req).await;
        completion.result.map_err(FsError::Io)?;
        let buf = io
            .buffer()
            .ok_or(FsError::Io(BlockError::PermissionDenied))?;
        // SAFETY: see `read_sector`.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), SECTOR_SIZE) };
        dst.copy_from_slice(src);
        Ok(())
    }

    /// Decode the root directory record from the PVD's embedded
    /// 34-byte field (ECMA-119 §8.4.18).
    pub fn root_record(&self) -> DirectoryRecord {
        let bytes: &[u8; 34] = &self.pvd.root_directory_record;
        // Re-use the sector-buffer helper — the embedded record is
        // guaranteed to be a well-formed 33-byte header (§9.1) +
        // single-byte file identifier (§9.1.11.1, value 0x00).
        read_directory_record(bytes, 0)
    }
}

impl<B: BlockDevice + 'static> FsInstance for Iso9660Volume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let record = self.root_record();
        let volume = self
            .self_weak
            .upgrade()
            .expect("Iso9660Volume::root called after drop");
        Arc::new(super::node::Iso9660Node::from_record(volume, &record))
    }

    fn name(&self) -> &str {
        "iso9660"
    }
}

// ── Helpers reachable to siblings (`node.rs`, tests) ───────────────

/// Read a contiguous run of `n_sectors` starting at `lba` into a
/// freshly-allocated `Vec<u8>`. Used by directory enumeration to
/// pull a whole extent into RAM at once. The vec is sized exactly
/// `n_sectors * SECTOR_SIZE`.
pub(crate) async fn read_extent<B: BlockDevice + 'static>(
    volume: &Iso9660Volume<B>,
    lba: u64,
    n_sectors: u32,
) -> Result<Vec<u8>, FsError> {
    let mut out = vec![0u8; n_sectors as usize * SECTOR_SIZE];
    for i in 0..n_sectors {
        let off = i as usize * SECTOR_SIZE;
        volume
            .read_sector(lba + i as u64, &mut out[off..off + SECTOR_SIZE])
            .await?;
    }
    Ok(out)
}
