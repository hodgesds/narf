//! UDF Volume management — AVDP lookup, VDS walk, mount, sector I/O.
//!
//! Clean-room implementation. Volume layout, descriptor walk, and
//! cap-bound DMA wiring are derived strictly from the public
//! references below — no GPL/LGPL UDF source consulted.
//!
//! References:
//! - ECMA-167 §3/8.4.2 (Volume Recognition Sequence + AVDP).
//! - ECMA-167 §3/10.2 (AVDP layout — locates the Main + Reserve VDS
//!   extents).
//! - ECMA-167 §3/10.6 (Logical Volume Descriptor — has the partition
//!   map array + a long_ad pointing at the File Set Descriptor).
//! - ECMA-167 §3/10.7.2 (Type-1 partition map — 6 bytes:
//!   [0]=type=1, [1]=length=6, [2..4]=volume_seq_num,
//!   [4..6]=partition_number).
//! - ECMA-167 §4/14.1 (File Set Descriptor — has the root
//!   directory's ICB long_ad).
//! - OSTA UDF 2.60 §2.2.3 (canonical AVDP locations: sector 256,
//!   last sector, last sector - 256).

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
    read_anchor, read_descriptor_tag, read_file_set, read_lvd_header, read_partition,
    tag_id, AnchorVolumeDescriptorPointer, FileSetDescriptor, LogicalVolumeDescriptorHeader,
    PartitionDescriptor,
};
use super::icb::{read_long_ad, LongAd};
use super::{AVDP_PRIMARY_SECTOR, SECTOR_SIZE};

// ── DMA / cap holder ────────────────────────────────────────────────

/// Cap → DmaBuffer pair owned by a `UdfVolume`. Minted once at
/// `mount()` via `narf_io::register_with_cap`; every sector op
/// derives a `Read` cap from this `Write` cap (per memory:
/// `Cap::bootstrap()` is forbidden in hot paths). `Drop` calls
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

// ── Public surface ──────────────────────────────────────────────────

/// A mounted UDF volume.
#[derive(Debug)]
pub struct UdfVolume<B: BlockDevice> {
    pub device: Arc<B>,
    pub domain: DomainId,
    pub self_weak: Weak<UdfVolume<B>>,
    /// Anchor that the mount used. Kept around for debugging /
    /// observability; the rest of the volume state is derived from
    /// it.
    pub anchor: AnchorVolumeDescriptorPointer,
    /// First Partition Descriptor decoded from the VDS. The MVP
    /// only supports volumes with a single partition (and a single
    /// Type-1 map referring to it).
    pub partition: PartitionDescriptor,
    /// Logical Volume Descriptor fixed prefix.
    pub lvd: LogicalVolumeDescriptorHeader,
    /// File Set Descriptor — the LVD's `logical_volume_contents_use`
    /// long_ad points at it, and it carries the root ICB.
    pub fsd: FileSetDescriptor,
    /// Decoded root-directory ICB (a long_ad lifted out of the FSD).
    pub root_icb: LongAd,
    /// Per-volume registered DMA scratch buffer + cap. See
    /// `VolumeIo` doc for why this is minted once at mount time.
    /// Held inside an `IrqSafeSpinLock` because every sector op
    /// holds it for a synchronous-copy span only and never across
    /// an `await`.
    io: IrqSafeSpinLock<VolumeIo>,
}

impl<B: BlockDevice + 'static> UdfVolume<B> {
    /// Mount a UDF volume.
    ///
    /// Procedure:
    ///   1. Locate the AVDP (ECMA-167 §3/10.2 + OSTA UDF 2.60
    ///      §2.2.3): try sector 256, then the last sector, then
    ///      last - 256.
    ///   2. Walk the Main VDS extent (ECMA-167 §3/10.2.2 →
    ///      §3/10.6) until a Terminating Descriptor (tag 8) appears
    ///      or the extent is exhausted, capturing the first
    ///      Partition Descriptor (tag 5) and Logical Volume
    ///      Descriptor (tag 6).
    ///   3. Decode the LVD's `logical_volume_contents_use` as a
    ///      `long_ad` pointing at the File Set Descriptor (ECMA-167
    ///      §3/10.6.7). Verify that the LVD has at least one
    ///      Type-1 partition map (ECMA-167 §3/10.7.2).
    ///   4. Read the FSD sector and lift the root directory ICB
    ///      (ECMA-167 §4/14.1.15).
    ///
    /// Requires `device.logical_block_size() == 2048`.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        if device.logical_block_size() as usize != SECTOR_SIZE {
            return Err(FsError::Unsupported);
        }

        // Allocate + register the per-volume scratch buffer. Mints
        // exactly one object-table slot for the lifetime of the
        // volume.
        let buffer = alloc_coherent(SECTOR_SIZE, domain)
            .map_err(|_| FsError::Io(BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap };

        let mut sector_buf = vec![0u8; SECTOR_SIZE];

        // ── Step 1: AVDP lookup ─────────────────────────────────
        let cap_blocks = device.capacity_blocks();
        let last_sector = cap_blocks.saturating_sub(1);
        let mut anchor: Option<AnchorVolumeDescriptorPointer> = None;
        let candidates: [u64; 3] = [
            AVDP_PRIMARY_SECTOR,
            last_sector,
            last_sector.saturating_sub(256),
        ];
        for &lsn in &candidates {
            if lsn >= cap_blocks {
                continue;
            }
            if Self::read_sector_into(&*device, &io, lsn, &mut sector_buf)
                .await
                .is_err()
            {
                continue;
            }
            let tag = read_descriptor_tag(&sector_buf, 0);
            if tag.tag_identifier == tag_id::ANCHOR_VOLUME_DESCRIPTOR_POINTER {
                anchor = Some(read_anchor(&sector_buf));
                break;
            }
        }
        let anchor = match anchor {
            Some(a) => a,
            None => {
                drop(io);
                return Err(FsError::Unsupported);
            }
        };

        // ── Step 2: walk the Main VDS extent ────────────────────
        let main_vds_loc = anchor.main_vds.extent_location as u64;
        let main_vds_len = anchor.main_vds.extent_length;
        let mut partition: Option<PartitionDescriptor> = None;
        let mut lvd_header: Option<LogicalVolumeDescriptorHeader> = None;
        // For the LVD we also need the partition map bytes that
        // follow the fixed header — Type-1 verification needs the
        // first map's type byte.
        let mut lvd_first_map_type: Option<u8> = None;

        let n_vds_sectors = (main_vds_len as u64).div_ceil(SECTOR_SIZE as u64);
        for i in 0..n_vds_sectors {
            let lsn = main_vds_loc + i;
            if lsn >= cap_blocks {
                break;
            }
            if Self::read_sector_into(&*device, &io, lsn, &mut sector_buf)
                .await
                .is_err()
            {
                break;
            }
            let tag = read_descriptor_tag(&sector_buf, 0);
            match tag.tag_identifier {
                tag_id::TERMINATING_DESCRIPTOR => break,
                tag_id::PARTITION_DESCRIPTOR if partition.is_none() => {
                    partition = Some(read_partition(&sector_buf, 0));
                }
                tag_id::LOGICAL_VOLUME_DESCRIPTOR if lvd_header.is_none() => {
                    let header = read_lvd_header(&sector_buf, 0);
                    let map_off =
                        core::mem::size_of::<LogicalVolumeDescriptorHeader>();
                    if header.number_of_partition_maps >= 1
                        && map_off + 2 <= sector_buf.len()
                    {
                        // Type-1 partition map (§3/10.7.2) — first
                        // byte is the map type. Bytes after that
                        // give the volume seq + partition number.
                        lvd_first_map_type = Some(sector_buf[map_off]);
                    }
                    lvd_header = Some(header);
                }
                _ => {} // Primary VD / Implementation Use / USD — skipped.
            }
        }
        let partition = match partition {
            Some(p) => p,
            None => {
                drop(io);
                return Err(FsError::Unsupported);
            }
        };
        let lvd = match lvd_header {
            Some(l) => l,
            None => {
                drop(io);
                return Err(FsError::Unsupported);
            }
        };
        // MVP: Type-1 only. Sparable / virtual / metadata maps are
        // out of scope (UDF 2.60 §2.2.10).
        if lvd_first_map_type != Some(1) {
            drop(io);
            return Err(FsError::Unsupported);
        }

        // ── Step 3: decode the FSD long_ad from the LVD ────────
        let fsd_long_ad = read_long_ad(&lvd.logical_volume_contents_use, 0);
        // The long_ad's LBN is partition-relative; the absolute
        // sector is `partition_starting_location + lbn`.
        let fsd_lsn =
            partition.partition_starting_location as u64 + fsd_long_ad.extent_lbn as u64;
        if fsd_lsn >= cap_blocks {
            drop(io);
            return Err(FsError::Unsupported);
        }

        // ── Step 4: read the FSD and lift the root ICB ─────────
        Self::read_sector_into(&*device, &io, fsd_lsn, &mut sector_buf).await?;
        let fsd_tag = read_descriptor_tag(&sector_buf, 0);
        if fsd_tag.tag_identifier != tag_id::FILE_SET_DESCRIPTOR {
            drop(io);
            return Err(FsError::Unsupported);
        }
        let fsd = read_file_set(&sector_buf, 0);
        let root_icb = read_long_ad(&fsd.root_directory_icb, 0);

        Ok(Arc::new_cyclic(|self_weak| UdfVolume {
            device,
            domain,
            self_weak: self_weak.clone(),
            anchor,
            partition,
            lvd,
            fsd,
            root_icb,
            io: IrqSafeSpinLock::new(io),
        }))
    }

    /// Translate a partition-relative `(partition_ref, lbn)` pair
    /// into an absolute LSN. The MVP only knows about partition
    /// reference 0 (the single Type-1 partition); other indices
    /// surface `FsError::Unsupported`.
    pub fn translate_long_ad(&self, ad: &LongAd) -> Result<u64, FsError> {
        if ad.partition_ref != 0 {
            return Err(FsError::Unsupported);
        }
        Ok(self.partition.partition_starting_location as u64 + ad.extent_lbn as u64)
    }

    /// Issue a one-sector read into `dst`. `dst` must be exactly
    /// [`SECTOR_SIZE`] bytes. Internally serialises on the volume's
    /// scratch buffer + cap.
    pub async fn read_sector(&self, lba: u64, dst: &mut [u8]) -> Result<(), FsError> {
        if dst.len() != SECTOR_SIZE {
            return Err(FsError::Io(BlockError::InvalidRange));
        }
        // Snapshot the cap (it's `Copy`); cannot hold the spinlock
        // across the I/O await.
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
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), SECTOR_SIZE) };
        dst.copy_from_slice(src);
        Ok(())
    }

    /// `read_sector` variant usable before the `Arc<UdfVolume>`
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
}

impl<B: BlockDevice + 'static> FsInstance for UdfVolume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let volume = self
            .self_weak
            .upgrade()
            .expect("UdfVolume::root called after drop");
        let icb = self.root_icb;
        Arc::new(super::node::UdfNode::root_from_icb(volume, icb))
    }

    fn name(&self) -> &str {
        "udf"
    }
}

// ── Helpers reachable to siblings (`node.rs`, tests) ───────────────

/// Read a contiguous run of `n_sectors` starting at `lba` into a
/// freshly-allocated `Vec<u8>`. Sized exactly `n_sectors *
/// SECTOR_SIZE`.
pub(crate) async fn read_extent<B: BlockDevice + 'static>(
    volume: &UdfVolume<B>,
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
