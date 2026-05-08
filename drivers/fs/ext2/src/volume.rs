//! ext2 volume management.
//!
//! Clean-room implementation. Volume mount, superblock + BGDT
//! decoding, inode-number-to-block-group math, and the indirect-block
//! pointer walk all derived strictly from the public references
//! below — no GPL Linux `fs/ext2/*`, GRUB, e2fsprogs, or BSD ext2
//! sources were consulted while writing this file.
//!
//! References:
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, §"Physical Layout", §"Block Groups",
//!   §"Inodes". <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_.
//! - OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{DirOps, FsError, FsInstance};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::sync::IrqSafeSpinLock;

use super::group_desc::{GroupDesc, GROUP_DESC_SIZE};
use super::inode::Inode;
use super::superblock::Superblock;

/// Cap → DmaBuffer pair owned by an Ext2Volume. The cap is minted
/// once at `mount()` via `narf_io::register_with_cap` and is the
/// load-bearing identifier in every `BlockRequest::buffer`. Drop
/// calls `unregister`, which bumps the epoch + frees the registry
/// slot + releases the underlying frame.
#[derive(Debug)]
struct VolumeIo {
    /// Owning cap for the registered DMA scratch buffer.
    cap: Cap<DmaBuffer, Write>,
    /// Logical block size of the underlying device — every
    /// `BlockRequest` is exactly this many bytes.
    lbs: usize,
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

/// One mounted ext2 volume.
#[derive(Debug)]
pub struct Ext2Volume<B: BlockDevice> {
    pub device: Arc<B>,
    pub superblock: Superblock,
    pub group_descs: Vec<GroupDesc>,
    pub domain: DomainId,
    pub self_weak: Weak<Ext2Volume<B>>,
    /// Per-volume scratch buffer + cap. Wrapped in a spinlock so
    /// every device-LBA op holds it for the synchronous-copy span
    /// only and never across an `await` (the lock would otherwise
    /// deadlock under cooperative async).
    io: IrqSafeSpinLock<VolumeIo>,
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Mount an ext2 volume. Reads the superblock at byte offset
    /// 1024 (in 512-byte sectors that's LBA 2), validates the
    /// `0xEF53` magic, then loads the block group descriptor table.
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        let lbs = device.logical_block_size() as usize;
        if lbs == 0 || 1024 % lbs != 0 && lbs % 1024 != 0 {
            // The driver assumes the device's logical block size is
            // a power-of-two factor of 1024 (or vice-versa). 512,
            // 1024, 2048, 4096 all qualify.
            return Err(FsError::Unsupported);
        }
        let buffer = alloc_coherent(lbs, domain)
            .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
        let cap = register_with_cap(buffer);
        let io = VolumeIo { cap, lbs };

        // Read 1024 bytes starting at byte 1024 — the superblock.
        // For a 512-byte LBS this is two LBA reads (LBA 2 and LBA
        // 3); for a 1024-byte LBS it's one (LBA 1); for a 4096-byte
        // LBS the superblock sits inside LBA 0 at byte 1024.
        let mut sb_bytes = vec![0u8; 1024];
        Self::read_byte_range_into(&*device, &io, 1024, &mut sb_bytes).await?;

        let superblock = match Superblock::parse(&sb_bytes) {
            Some(s) => s,
            None => {
                unregister(io.cap);
                core::mem::forget(io); // unregister already ran
                return Err(FsError::Unsupported);
            }
        };

        // Block group descriptor table starts at the block after
        // the superblock. With a 1-KiB block volume that's block 2;
        // with a 2-KiB or 4-KiB block volume it's block 1. The
        // canonical formula:
        //
        //     bgdt_block = s_first_data_block + 1
        //
        // ext2 design paper, §"Block Groups".
        let bs = superblock.block_size() as u64;
        let group_count = superblock.block_group_count() as usize;
        let bgdt_size_bytes = (group_count * GROUP_DESC_SIZE) as u64;
        let bgdt_block_offset = (superblock.first_data_block + 1) as u64 * bs;

        let mut bgdt_bytes = vec![0u8; bgdt_size_bytes as usize];
        Self::read_byte_range_into(&*device, &io, bgdt_block_offset, &mut bgdt_bytes).await?;

        let mut group_descs = Vec::with_capacity(group_count);
        for i in 0..group_count {
            let off = i * GROUP_DESC_SIZE;
            let gd = GroupDesc::parse(&bgdt_bytes[off..off + GROUP_DESC_SIZE])
                .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
            group_descs.push(gd);
        }

        Ok(Arc::new_cyclic(|self_weak| Ext2Volume {
            device,
            superblock,
            group_descs,
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
        }))
    }

    /// Filesystem block size in bytes.
    pub fn block_size(&self) -> usize {
        self.superblock.block_size() as usize
    }

    /// Number of 32-bit pointers per indirect block.
    pub fn pointers_per_block(&self) -> usize {
        self.block_size() / 4
    }

    /// Read one filesystem block (`block_size()` bytes) into `dst`.
    /// Internally this may cost multiple device-LBA reads if the
    /// device's logical block size is smaller than the FS block
    /// size, or one partial read if larger.
    pub async fn read_block(&self, block_no: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let bs = self.block_size();
        if dst.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let byte_off = block_no * bs as u64;
        self.read_byte_range(byte_off, dst).await
    }

    /// Read `dst.len()` bytes starting at the device byte offset
    /// `byte_off`. Internally serialises on the volume's scratch
    /// buffer + cap.
    pub async fn read_byte_range(
        &self,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        // Cap is `Copy`; LBS is small. Snapshot under the lock.
        let (cap, lbs) = {
            let g = self.io.lock();
            (g.cap, g.lbs)
        };
        Self::read_byte_range_with(&*self.device, cap, lbs, &self.io, byte_off, dst).await
    }

    /// Variant of `read_byte_range` usable before the `Ext2Volume`
    /// `Arc` exists — `mount()` calls this through a `&VolumeIo`
    /// directly.
    async fn read_byte_range_into(
        device: &B,
        io: &VolumeIo,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let lbs = io.lbs;
        let mut cursor = 0usize;
        while cursor < dst.len() {
            let abs = byte_off + cursor as u64;
            let lba = abs / lbs as u64;
            let in_lba = (abs % lbs as u64) as usize;
            let want = core::cmp::min(dst.len() - cursor, lbs - in_lba);

            let req = BlockRequest {
                op: BlockOp::Read,
                lba,
                blocks: 1,
                buffer: io
                    .cap
                    .derive::<Read>()
                    .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            let completion = device.submit(req).await;
            completion.result.map_err(FsError::Io)?;

            let buf = io
                .buffer()
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: the registry holds the only `Arc<DmaBuffer>`
            // outside this clone; ext2 mount serialises sector ops
            // via the outer spinlock so no other CPU/task is racing
            // the buffer bytes during this copy. Identity-mapped
            // phys backs the read.
            let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
            dst[cursor..cursor + want].copy_from_slice(&src[in_lba..in_lba + want]);
            cursor += want;
        }
        Ok(())
    }

    /// Internal helper used by `read_byte_range`. Holds the volume's
    /// cap-bound buffer for one sector at a time, serialising on
    /// `io` for the brief synchronous-copy span only.
    async fn read_byte_range_with(
        device: &B,
        cap: Cap<DmaBuffer, Write>,
        lbs: usize,
        io_lock: &IrqSafeSpinLock<VolumeIo>,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let mut cursor = 0usize;
        while cursor < dst.len() {
            let abs = byte_off + cursor as u64;
            let lba = abs / lbs as u64;
            let in_lba = (abs % lbs as u64) as usize;
            let want = core::cmp::min(dst.len() - cursor, lbs - in_lba);

            let req = BlockRequest {
                op: BlockOp::Read,
                lba,
                blocks: 1,
                buffer: cap
                    .derive::<Read>()
                    .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                qos: QosHint::Latency,
                user_tag: 0,
            };
            let completion = device.submit(req).await;
            completion.result.map_err(FsError::Io)?;

            let buf = io_lock
                .lock()
                .buffer()
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: see read_byte_range_into.
            let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), lbs) };
            dst[cursor..cursor + want].copy_from_slice(&src[in_lba..in_lba + want]);
            cursor += want;
        }
        Ok(())
    }

    /// `(group, index)` for an inode number. Inode numbers are
    /// 1-based on disk; the math (per the design paper §"Inodes"):
    ///
    /// ```text
    /// group = (inode - 1) / s_inodes_per_group
    /// index = (inode - 1) % s_inodes_per_group
    /// ```
    pub fn inode_group_and_index(&self, inode_no: u32) -> Option<(u32, u32)> {
        if inode_no == 0 {
            return None;
        }
        let zero = inode_no - 1;
        let group = zero / self.superblock.inodes_per_group;
        let index = zero % self.superblock.inodes_per_group;
        if (group as usize) >= self.group_descs.len() {
            return None;
        }
        Some((group, index))
    }

    /// Read the on-disk inode `inode_no`.
    pub async fn read_inode(&self, inode_no: u32) -> Result<Inode, FsError> {
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let gd = &self.group_descs[group as usize];
        let inode_size = self.superblock.inode_size_bytes();
        let bs = self.block_size() as u64;

        let table_byte_off = gd.inode_table as u64 * bs;
        let inode_byte_off = table_byte_off + (index as u64) * inode_size as u64;

        // Only need 128 bytes — the rest of the inode (rev-1+ extra
        // fields) is unused by this driver.
        let mut buf = vec![0u8; 128];
        self.read_byte_range(inode_byte_off, &mut buf).await?;
        Inode::parse(&buf).ok_or(FsError::Io(narf_block::BlockError::IOError))
    }

    /// Resolve the `i`th logical block of `inode` to its physical
    /// block number. Returns `Ok(0)` for a hole (sparse file).
    /// Reads at most three indirect blocks to follow the chain.
    pub async fn map_block(&self, inode: &Inode, logical: u64) -> Result<u32, FsError> {
        let p = self.pointers_per_block() as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;

        if logical < direct_max {
            return Ok(inode.block[logical as usize]);
        }
        if logical < single_max {
            let idx = logical - direct_max;
            let l1 = inode.block[super::inode::SINGLE_IND_IDX];
            return self.read_indirect(l1, idx).await;
        }
        if logical < double_max {
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let l2_block = inode.block[super::inode::DOUBLE_IND_IDX];
            let middle = self.read_indirect(l2_block, l1).await?;
            return self.read_indirect(middle, l0).await;
        }
        if logical < triple_max {
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let l3_block = inode.block[super::inode::TRIPLE_IND_IDX];
            let middle = self.read_indirect(l3_block, l2).await?;
            let leaf = self.read_indirect(middle, l1).await?;
            return self.read_indirect(leaf, l0).await;
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// Read pointer `index` from the indirect block `block_no`.
    /// `block_no == 0` is a hole — returns 0.
    async fn read_indirect(&self, block_no: u32, index: u64) -> Result<u32, FsError> {
        if block_no == 0 {
            return Ok(0);
        }
        if index >= self.pointers_per_block() as u64 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let bs = self.block_size();
        let mut buf = vec![0u8; bs];
        self.read_block(block_no as u64, &mut buf).await?;
        let off = (index as usize) * 4;
        Ok(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    }
}

impl<B: BlockDevice + 'static> FsInstance for Ext2Volume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        // The root directory is always inode 2 — see EXT2_ROOT_INO.
        // Stat is filled in lazily on the first `stat()` call; for
        // VFS bootstrap purposes we just hand back a dir-typed
        // node.
        Arc::new(super::node::Ext2Node::new(
            self.self_weak
                .upgrade()
                .expect("Ext2Volume root called after drop"),
            super::EXT2_ROOT_INO,
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::DIR_RO,
                mtime_cycles: 0,
            },
        ))
    }

    fn name(&self) -> &str {
        "ext2"
    }
}
